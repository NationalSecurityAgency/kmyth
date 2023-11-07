# create key and certificate for test "Certificate Authority (CA)"
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out ca_priv_test.pem
openssl req -new \
            -x509 \
            -key ca_priv_test.pem \
            -subj "/C=US/O=Kmyth/CN=TestCA" \
            -sha256 \
            -days 365 \
            -out ca_cert_test.pem

# create key and certificate for test "client"
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out client_priv_test.pem
openssl req -new \
            -key client_priv_test.pem \
            -subj "/C=US/O=Kmyth/CN=TestClient" \
            -addext "subjectAltName = IP:127.0.0.1" \
            -sha256 \
            -out client_cert_test.csr
openssl x509 -req \
             -in client_cert_test.csr \
             -CA ca_cert_test.pem \
             -CAkey ca_priv_test.pem \
             -copy_extensions copy \
             -CAcreateserial \
             -sha256 \
             -days 365 \
             -out client_cert_test.pem

# create key and certificate for test "ECDH proxy"
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out proxy_priv_test.pem
openssl req -new \
            -key proxy_priv_test.pem \
            -subj "/C=US/O=Kmyth/CN=TestProxy" \
            -addext "subjectAltName = IP:127.0.0.1" \
            -sha256 \
            -out proxy_cert_test.csr
openssl x509 -req \
             -in proxy_cert_test.csr \
             -CA ca_cert_test.pem \
             -CAkey ca_priv_test.pem \
             -copy_extensions copy \
             -CAcreateserial \
             -sha256 \
             -days 365 \
             -out proxy_cert_test.pem

# create key and certificate for test "key server"
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out server_priv_test.pem
openssl req -new \
            -key server_priv_test.pem \
            -subj "/C=US/O=Kmyth/CN=TestServer" \
            -addext "subjectAltName = IP:127.0.0.1" \
            -sha256 \
            -out server_cert_test.csr
openssl x509 -req \
             -in server_cert_test.csr \
             -CA ca_cert_test.pem \
             -CAkey ca_priv_test.pem \
             -copy_extensions copy \
             -CAcreateserial \
             -sha256 \
             -days 365 \
             -out server_cert_test.pem
