#[cfg(test)]
mod tests {
    use ft::network::client::connect_to_peer;
    use ft::network::listenter::start_listener;
    use rand_core::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    use std::fs;
    use tokio::time::{Duration, timeout};

    #[tokio::test]
    async fn test_key_exchange() {
        let sender_secret = EphemeralSecret::random_from_rng(OsRng);
        let sender_public = PublicKey::from(&sender_secret);
        let receiver_secret = EphemeralSecret::random_from_rng(OsRng);
        let receiver_public = PublicKey::from(&receiver_secret);
        let sender_shared = sender_secret.diffie_hellman(&receiver_public);
        let receiver_shared = receiver_secret.diffie_hellman(&sender_public);
        assert_eq!(sender_shared.to_bytes(), receiver_shared.to_bytes());
    }

    // TODO: use tmp file
    #[tokio::test]
    async fn test_connect_and_send_request() {
        let port = 8081;

        tokio::spawn(async move {
            start_listener(port).await.unwrap();
        });

        tokio::time::sleep(Duration::from_millis(100)).await;

        fs::write("test.txt", "Hello").unwrap();
        let result = timeout(
            Duration::from_secs(2),
            connect_to_peer("127.0.0.1:8081", "test.txt"),
        )
        .await;
        assert!(result.is_ok(), "Failed to connect and send request");
        fs::remove_file("test.txt").unwrap();
    }

    #[tokio::test]
    async fn test_receive_file() {
        let port = 8083;

        tokio::spawn(async move {
            start_listener(port).await.unwrap();
        });
        tokio::time::sleep(Duration::from_millis(100)).await;

        fs::write("send_test.txt", "Hello, world!").unwrap();

        let result = timeout(
            Duration::from_secs(2),
            connect_to_peer("127.0.0.1:8083", "send_test.txt"),
        )
        .await;
        assert!(result.is_ok(), "Failed to send file");

        let received = fs::read_to_string("send_test.txt").unwrap();
        assert_eq!(received, "Hello, world!");

        fs::remove_file("send_test.txt").unwrap();
    }
}
