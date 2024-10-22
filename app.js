import express from 'express'
import router from './routes/route'
import cookieParser from 'cookie-parser'

const app = express()

app.use(express.json())
app.use(cookieParser())

const PORT = process.env.PORT || 3000

app.use('/api', router)

app.listen(PORT, () => {
    console.log(`Server listening on port: http://localhost:${PORT}`)
})