const jsonServer = require("json-server");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt"); 
const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();
const bodyParser = require("body-parser");

server.use(middlewares);
server.use(bodyParser.json());

const SECRET_KEY = "password"; 
const EXPIRES_IN = "1h"; 

// Ruta de login para autenticar usuarios y devolver un token
server.post("/login", async (req, res) => {
  const { username, password } = req.body;
  
  const users = router.db.get("users").value();
  const user = users.find((u) => u.username === username);

  if (!user) {
    return res.status(401).json({ error: "Usuario no encontrado" });
  }

  const isValid = await bcrypt.compare(password, user.password);

  if (!isValid) {
    return res.status(401).json({ error: "Contraseña incorrecta" });
  }

  // Generar token JWT
  const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: EXPIRES_IN });

  res.json({ token });
});

server.post("/verificar-token", (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "No se proporcionó token" });
  }

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: "Token inválido o expirado" });
    }
    res.json({ message: "Token válido", user: decoded });
  });
});


server.use(router);

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`JSON Server corriendo en el puerto ${PORT}`);
});
