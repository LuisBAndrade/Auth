import dotenv from 'dotenv'
import pg from 'pg'

dotenv.config()

const { Client } = pg

const client = new Client({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD
})

client.connect((err) => {
    if (err) {
        console.error('Error connecting to the database', err)
        return
    }
    console.log('Connected to the database')

    client.query(`
        CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
        )
    `, (err) => {
        if (err) {
            console.error('Error creating users table', err)
            return
        }
        console.log('Users table created')
    })
})

export default client