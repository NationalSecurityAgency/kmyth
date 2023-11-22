# create key and certificate for test "Certificate Authority (CA)"
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out ca_priv.pem

openssl req -new \
            -x509 \
            -config ca.cnf \
            -key ca_priv.pem \
            -days 365 \
            -out ca_cert.pem

# create key and certificate for test "client"
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out client_priv.pem

openssl req -new \
            -config client.cnf \
            -key client_priv.pem \
            -out client.csr

openssl x509 -req \
             -in client.csr \
             -extfile client.cnf \
             -extensions v3_ext \
             -CA ca_cert.pem \
             -CAkey ca_priv.pem \
             -CAcreateserial \
             -days 365 \
             -out client_cert.pem

# create key and certificate for test "ECDH proxy"
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out proxy_priv.pem

openssl req -new \
            -config proxy.cnf \
            -key proxy_priv.pem \
            -out proxy.csr

openssl x509 -req \
             -in proxy.csr \
             -extfile proxy.cnf \
             -extensions v3_ext \
             -CA ca_cert.pem \
             -CAkey ca_priv.pem \
             -CAcreateserial \
             -days 365 \
             -out proxy_cert.pem

# create key and certificate for test "key server"
openssl ecparam -name secp521r1 \
                -genkey \
                -noout \
                -out server_priv.pem

openssl req -new \
            -config server.cnf \
            -key server_priv.pem \
            -out server.csr
            
openssl x509 -req \
             -in server.csr \
             -extfile server.cnf \
             -extensions v3_ext \
             -CA ca_cert.pem \
             -CAkey ca_priv.pem \
             -CAcreateserial \
             -days 365 \
             -out server_cert.pem
