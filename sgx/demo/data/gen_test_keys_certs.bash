openssl ecparam -name secp384r1 -genkey -noout -out client_priv_test.pem
openssl req -new -x509 -key client_priv_test.pem -subj "/C=US/O=Kmyth/CN=TestClient" -out client_cert_test.pem -days 365

openssl ecparam -name secp384r1 -genkey -noout -out server_priv_test.pem
openssl req -new -x509 -key server_priv_test.pem -subj "/C=US/O=Kmyth/CN=TestServer" -out server_cert_test.pem -days 365

