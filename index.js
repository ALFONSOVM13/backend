const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const cors = require('cors');

const app = express();
const PORT = 42987;



app.use(cors()); 
app.use(express.json());
app.use(cookieParser());


const db = mysql.createConnection({
    host: 'viaduct.proxy.rlwy.net',
    user: 'root',
    password: '45fBD1gf5EcG54c5e4afbCCc5d5-B6g3',
    database: 'railway',
    port: '42987'
});

db.connect((err) => {
    if (err) {
        console.error('Error al conectar a la base de datos:', err);
    } else {
        console.log('Conexión a la base de datos exitosa.');
    }
});

const secret = 'clave123';

const authenticateToken = (req, res, next) => {
    const authorizationHeader = req.headers['authorization'];

    if (!authorizationHeader) {
        console.error('No se proporcionó el token');
        return res.sendStatus(401);
    }

    const [bearer, token] = authorizationHeader.split(' ');

    if (!token || bearer.toLowerCase() !== 'bearer') {
        console.error('Formato de token inválido');
        return res.sendStatus(401);
    }

    jwt.verify(token, secret, (err, user) => {
        if (err) {
            console.error('Error al verificar el token:', err);
            return res.status(403).json({ error: 'Token no válido' });
        }

        req.user = user;
        next();
    });
};

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const user = await getUserByUsername(username);

        if (user && await bcrypt.compare(password, user.password)) {
            const token = generateToken(user.id, user.username);

            res.cookie('token', token, { httpOnly: true });

            res.json({ message: 'Inicio de sesión exitoso', token });
        } else {
            res.status(401).json({ error: 'Credenciales inválidas' });
        }
    } catch (error) {
        console.error('Error al realizar la autenticación:', error);
        res.status(500).json({ error: 'Error al realizar la autenticación' });
    }
});



app.post('/register', async (req, res) => {
    const { username, password, firstName, lastName, email } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.query(
            'INSERT INTO users (username, password, firstName, lastName, email) VALUES (?, ?, ?, ?, ?)',
            [username, hashedPassword, firstName, lastName, email],
            (error, results) => {
                if (error) {
                    console.error('Error en la inserción a la base de datos:', error);
                    return res.status(500).send('Error en el registro: ' + error.message);
                }

                res.status(200).send('Registro exitoso');
            }
        );
    } catch (error) {
        console.error('Error al encriptar la contraseña:', error);
        return res.status(500).send('Error en el registro: ' + error.message);
    }
});




// Ruta protegida que requiere autenticación
app.get('/home', authenticateToken, (req, res) => {
    // Verifica el token
    jwt.verify(req.token, secret, (err, user) => {
        if (err) {
            console.error('Error al verificar el token:', err);
            return res.sendStatus(403);
        }

        res.send('Accediste a una ruta protegida');
    });
});

// Función para obtener un usuario por nombre de usuario
const getUserByUsername = (username) => {
    return new Promise((resolve, reject) => {
        db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
            if (err) {
                reject(err);
            } else {
                resolve(results.length > 0 ? results[0] : null);
            }
        });
    });
};

app.post('/checkuser', async (req, res) => {
    const { username, email } = req.body;

    try {
        const userByUsername = await getUserByUsername(username);
        const userByEmail = await getUserByEmail(email);

        if (userByUsername || userByEmail) {
            res.json({ exists: true });
        } else {
            res.json({ exists: false });
        }
    } catch (error) {
        console.error('Error al verificar el usuario o correo electrónico:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

const getUserByEmail = (email) => {
    return new Promise((resolve, reject) => {
        db.query('SELECT * FROM users WHERE email = ?', [email], (err, results) => {
            if (err) {
                reject(err);
            } else {
                resolve(results.length > 0 ? results[0] : null);
            }
        });
    });
};
app.get('/userinfo', authenticateToken, (req, res) => {
    const userId = req.user.id;

    // Consulta la base de datos para obtener los detalles del usuario
    db.query('SELECT username, firstName, lastName,email FROM users WHERE id = ?', [userId], (err, results) => {
        if (err) {
            console.error('Error al obtener la información del usuario desde la base de datos:', err);
            res.status(500).json({ error: 'Error interno del servidor' });
        } else {
            console.log('Resultados de la consulta:', results); 
            const userData = results[0];

            if (userData) {
                console.log('Usuario encontrado:', userData); 
                res.json(userData);
            } else {
                console.log('Usuario no encontrado'); 
                res.status(404).json({ error: 'Usuario no encontrado' });
            }
        }
    });
});

const generateToken = (userId, username) => {
    return jwt.sign({ id: userId, username }, secret, { expiresIn: '15m' });
};

app.listen(PORT, () => {
    console.log(`Servidor escuchando en el puerto ${PORT}`);
});
