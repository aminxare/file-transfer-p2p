#[cfg(test)]
mod tests {
    use ft::network::client::connect_to_peer;
    use ft::network::listener::start_listener;
    use std::fs;
    use tokio::time::{Duration, timeout};
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_full_file_transfer() {
        let dir = tempdir().expect("Failed to create temp dir");
        let send_path = dir.path().join("send.txt");
        let recv_path = dir.path().join("recv_send.txt");
        
        let content = "Hello, this is a secure P2P file transfer test!";
        fs::write(&send_path, content).expect("Failed to write test file");

        let port = 9000;

        // Start listener in a separate task
        let _server = tokio::spawn(async move {
            // We need to change the current directory for the server task 
            // so it saves the file in the temp dir.
            // Actually, receive_file currently uses a hardcoded "recv_{file_name}".
            // To make it testable, we'll just run the test in the temp dir.
            std::env::set_current_dir(dir.path()).unwrap();
            start_listener(port).await.unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Connect and send file
        let result = timeout(
            Duration::from_secs(5),
            connect_to_peer("127.0.0.1:9000", send_path.to_str().unwrap()),
        )
        .await;

        assert!(result.is_ok(), "File transfer timed out or failed: {:?}", result);
        assert!(result.unwrap().is_ok(), "connect_to_peer returned error");

        // Verify the received file
        // Wait a bit for the file to be flushed/closed
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        assert!(recv_path.exists(), "Received file does not exist at {:?}", recv_path);
        let received_content = fs::read_to_string(&recv_path).expect("Failed to read received file");
        assert_eq!(content, received_content);
    }
}
