import http from 'node:http'

const port = Number(process.env.E2E_UPSTREAM_PORT || 18000)

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' })
  res.end('upstream-ok')
})

server.listen(port, '127.0.0.1', () => {
  console.log(`e2e upstream on ${port}`)
})
