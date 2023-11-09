# setup CA resources, if not previously configured
touch index.txt
touch index.txt.attr

# create key and certificate for test "Certificate Authority (CA)"
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out ca_test.key

openssl req -new \
            -x509 \
            -config openssl.cnf \
            -extensions v3_ca \
            -subj "/C=US/O=Kmyth/CN=TestCA" \
            -key ca_test.key \
            -sha256 \
            -days 365 \
            -out ca_test.crt

# create key and certificate for test "client"
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out client_test.key

openssl req -new \
            -x509 \
            -key client_test.key \
            -subj "/C=US/O=Kmyth/CN=TestClient" \
            -config openssl.cnf \
            -extensions v3_client \
            -CA ca_test.crt \
            -CAkey ca_test.key \
            -sha256 \
            -days 365 \
            -out client_test.crt

# create key and certificate for test "ECDH proxy"
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out proxy_test.key

openssl req -new \
            -x509 \
            -key proxy_test.key \
            -subj "/C=US/O=Kmyth/CN=TestProxy" \
            -config openssl.cnf \
            -extensions v3_proxy \
            -CA ca_test.crt \
            -CAkey ca_test.key \
            -sha256 \
            -days 365 \
            -out proxy_test.crt

# create key and certificate for test "key server"
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out server_test.key

openssl req -new \
            -x509 \
            -key server_test.key \
            -subj "/C=US/O=Kmyth/CN=TestServer" \
            -config openssl.cnf \
            -extensions v3_server \
            -CA ca_test.crt \
            -CAkey ca_test.key \
            -sha256 \
            -days 365 \
            -out server_test.crt
