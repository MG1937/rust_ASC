use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::asc_client::query::{QueryError, QueryErrorCode};

#[derive(Clone)]
pub(super) struct Executor {
    permits: Arc<Semaphore>,
    threads: usize,
    shutdown: CancellationToken,
}

impl Executor {
    pub(super) fn new(parallelism: usize) -> Self {
        let parallelism = parallelism.max(1);
        let concurrency = parallelism.min(2);
        Self {
            permits: Arc::new(Semaphore::new(concurrency)),
            threads: (parallelism / concurrency).max(1),
            shutdown: CancellationToken::new(),
        }
    }

    pub(super) fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    pub(super) async fn run<T: Send + 'static>(
        &self,
        cancelled: CancellationToken,
        work: impl FnOnce(usize) -> Result<T, QueryError> + Send + 'static,
    ) -> Result<T, QueryError> {
        let permit = tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => return Err(cancelled_error()),
            _ = cancelled.cancelled() => return Err(cancelled_error()),
            permit = self.permits.clone().acquire_owned() => permit.map_err(|_| cancelled_error())?,
        };
        let threads = self.threads;
        let work_cancelled = cancelled.clone();
        let shutdown = self.shutdown.clone();
        let task = tokio::task::spawn_blocking(move || {
            // Cancellation must not release capacity while CPU work continues.
            let _permit = permit;
            if work_cancelled.is_cancelled() || shutdown.is_cancelled() {
                return Err(cancelled_error());
            }
            work(threads)
        });
        tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => Err(cancelled_error()),
            _ = cancelled.cancelled() => Err(cancelled_error()),
            result = task => result.map_err(|error|
                QueryError::new(QueryErrorCode::QueryFailed, error.to_string()))?,
        }
    }
}

fn cancelled_error() -> QueryError {
    QueryError::new(QueryErrorCode::Cancelled, "query cancelled")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::sync::oneshot;

    #[test]
    fn automatic_budget() {
        for (p, c, t) in [(0, 1, 1), (1, 1, 1), (2, 2, 1), (3, 2, 1), (16, 2, 8)] {
            let executor = Executor::new(p);
            assert_eq!(executor.permits.available_permits(), c);
            assert_eq!(executor.threads, t);
        }
    }

    #[tokio::test]
    async fn running_cancellation_keeps_its_permit_and_queued_cancellation_never_runs() {
        let executor = Executor::new(1);
        let first_cancel = CancellationToken::new();
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let first = tokio::spawn({
            let executor = executor.clone();
            let token = first_cancel.clone();
            async move {
                executor
                    .run(token, move |_| {
                        let _ = started_tx.send(());
                        let _ = release_rx.recv();
                        Ok(())
                    })
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .unwrap()
            .unwrap();
        first_cancel.cancel();
        assert_eq!(
            first.await.unwrap().unwrap_err().code,
            QueryErrorCode::Cancelled
        );
        assert_eq!(executor.permits.available_permits(), 0);

        let queued_cancel = CancellationToken::new();
        let queued = executor.run::<()>(queued_cancel.clone(), |_| panic!("queued query ran"));
        tokio::pin!(queued);
        // Poll once to ensure this request really entered the semaphore queue.
        assert!(futures_poll_pending(queued.as_mut()).await);
        queued_cancel.cancel();
        assert_eq!(queued.await.unwrap_err().code, QueryErrorCode::Cancelled);
        release_tx.send(()).unwrap();
        tokio::time::timeout(
            Duration::from_secs(5),
            executor.run(CancellationToken::new(), |_| Ok(())),
        )
        .await
        .unwrap()
        .unwrap();
    }

    async fn futures_poll_pending<F: std::future::Future>(
        mut future: std::pin::Pin<&mut F>,
    ) -> bool {
        std::future::poll_fn(|cx| std::task::Poll::Ready(future.as_mut().poll(cx).is_pending()))
            .await
    }

    #[tokio::test]
    async fn two_queries_can_run_but_a_third_waits_and_shutdown_cancels_it() {
        let executor = Executor::new(8);
        let mut releases = Vec::new();
        let mut running = Vec::new();
        for _ in 0..2 {
            let (started_tx, started_rx) = oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            releases.push(release_tx);
            running.push(tokio::spawn({
                let executor = executor.clone();
                async move {
                    executor
                        .run(CancellationToken::new(), move |threads| {
                            assert_eq!(threads, 4);
                            let _ = started_tx.send(());
                            let _ = release_rx.recv();
                            Ok(())
                        })
                        .await
                }
            }));
            tokio::time::timeout(Duration::from_secs(5), started_rx)
                .await
                .unwrap()
                .unwrap();
        }
        let third = executor.run(CancellationToken::new(), |_| panic!("queued query ran"));
        tokio::pin!(third);
        assert!(futures_poll_pending(third.as_mut()).await);
        executor.shutdown_token().cancel();
        let result: Result<(), QueryError> = third.await;
        assert_eq!(result.unwrap_err().code, QueryErrorCode::Cancelled);
        assert_eq!(executor.permits.available_permits(), 0);
        for release in releases {
            let _ = release.send(());
        }
        for task in running {
            let _ = task.await.unwrap();
        }
    }
}
