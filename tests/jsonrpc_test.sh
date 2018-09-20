curl -i -X POST \
   -H "Content-Type: application/json; indent=4" \
   -d '{
    "jsonrpc": "2.0",
    "method": "gettags",
    "params": {},
    "id": "1"
}' http://localhost:8080/jsonrpc
