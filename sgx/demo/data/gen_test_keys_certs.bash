# create key and certificate for test "Certificate Authority (CA)"
openssl req -x509 \
            -batch \
            -noenc \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:secp521r1 \
            -config openssl.cnf \
            -section req_ca \
            -days 30 \
            -keyout ca_priv.pem \
            -out ca_cert.pem

# create key and certificate for test "client"
openssl req -x509 \
            -batch \
            -noenc \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:secp521r1 \
            -config openssl.cnf \
            -section req_client \
            -CA ca_cert.pem \
            -CAkey ca_priv.pem \
            -days 30 \
            -keyout client_priv.pem \
            -out client_cert.pem

# create key and certificate for test "ECDH proxy"
openssl req -x509 \
            -batch \
            -noenc \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:secp521r1 \
            -config openssl.cnf \
            -section req_proxy \
            -CA ca_cert.pem \
            -CAkey ca_priv.pem \
            -days 30 \
            -keyout proxy_priv.pem \
            -out proxy_cert.pem

# create key and certificate for test "key server"
openssl req -x509 \
            -batch \
            -noenc \
            -newkey ec \
            -pkeyopt ec_paramgen_curve:secp521r1 \
            -config openssl.cnf \
            -section req_server \
            -CA ca_cert.pem \
            -CAkey ca_priv.pem \
            -days 30 \
            -keyout server_priv.pem \
            -out server_cert.pem
