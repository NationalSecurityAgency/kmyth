openssl ecparam -name secp521r1 -genkey -noout -out ca_priv_test.pem
openssl req -new -x509 -key ca_priv_test.pem -subj "/C=US/O=Kmyth/CN=TestCA" -out ca_cert_test.pem -days 365

openssl ecparam -name secp521r1 -genkey -noout -out client_priv_test.pem
openssl req -new -sha256 -key client_priv_test.pem -subj "/C=US/O=Kmyth/CN=TestClient" -out client_cert_test.csr
openssl x509 -req -in client_cert_test.csr -CA ca_cert_test.pem -CAkey ca_priv_test.pem -CAcreateserial -out client_cert_test.pem -days 365 -sha256

openssl ecparam -name secp521r1 -genkey -noout -out proxy_priv_test.pem
openssl req -new -sha256 -key proxy_priv_test.pem -subj "/C=US/O=Kmyth/CN=TestProxy" -out proxy_cert_test.csr
openssl x509 -req -in proxy_cert_test.csr -CA ca_cert_test.pem -CAkey ca_priv_test.pem -CAcreateserial -out proxy_cert_test.pem -days 365 -sha256

openssl ecparam -name secp521r1 -genkey -noout -out server_priv_test.pem
openssl req -new -sha256 -key server_priv_test.pem -subj "/C=US/O=Kmyth/CN=127.0.0.1" -out server_cert_test.csr
openssl x509 -req -in server_cert_test.csr -CA ca_cert_test.pem -CAkey ca_priv_test.pem -CAcreateserial -out server_cert_test.pem -days 365 -sha256
