const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./database");

const app = express();
const PORT = 3000;
const JWT_SECRET = "seu_super_secret_key_aqui";

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

function verificarToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Token não fornecido" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.usuario = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function verificarAdmin(req, res, next) {
  if (req.usuario.tipo_usuario !== "ADMIN") {
    return res.status(403).json({ error: "Acesso negado. Apenas administradores podem executar esta ação" });
  }
  next();
}

app.post("/api/auth/registro", async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
      return res.status(400).json({ error: "Nome, email e senha são obrigatórios" });
    }

    db.get("SELECT * FROM USUARIO WHERE email = ?", [email], async (err, row) => {
      if (row) {
        return res.status(400).json({ error: "Email já cadastrado" });
      }

      try {
        const hash = await bcrypt.hash(senha, 10);

        db.run("INSERT INTO USUARIO (nome, email, senha_hash, tipo_usuario) VALUES (?, ?, ?, ?)", [nome, email, hash, "USUARIO"], function (err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }

          const token = jwt.sign({ id: this.lastID, email, tipo_usuario: "USUARIO" }, JWT_SECRET, { expiresIn: "24h" });

          res.status(201).json({
            id: this.lastID,
            nome,
            email,
            tipo_usuario: "USUARIO",
            token,
          });
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, senha } = req.body;

    if (!email || !senha) {
      return res.status(400).json({ error: "Email e senha são obrigatórios" });
    }

    db.get("SELECT * FROM USUARIO WHERE email = ?", [email], async (err, usuario) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      if (!usuario) {
        return res.status(401).json({ error: "Email ou senha incorretos" });
      }

      try {
        const senhaValida = await bcrypt.compare(senha, usuario.senha_hash);

        if (!senhaValida) {
          return res.status(401).json({ error: "Email ou senha incorretos" });
        }

        const token = jwt.sign({ id: usuario.id, email: usuario.email, tipo_usuario: usuario.tipo_usuario }, JWT_SECRET, { expiresIn: "24h" });

        res.json({
          id: usuario.id,
          nome: usuario.nome,
          email: usuario.email,
          tipo_usuario: usuario.tipo_usuario,
          token,
        });
      } catch (error) {
        res.status(500).json({ error: error.message });
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get("/api/me", verificarToken, (req, res) => {
  db.get("SELECT id, nome, email, tipo_usuario FROM USUARIO WHERE id = ?", [req.usuario.id], (err, usuario) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (!usuario) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    res.json(usuario);
  });
});

app.delete("/api/admin/usuarios/:id", verificarToken, verificarAdmin, (req, res) => {
  const usuarioId = req.params.id;

  if (!usuarioId) {
    return res.status(400).json({ error: "ID do usuário é obrigatório" });
  }

  if (parseInt(usuarioId) === req.usuario.id) {
    return res.status(400).json({ error: "Você não pode deletar sua própria conta" });
  }

  db.get("SELECT id, email FROM USUARIO WHERE id = ?", [usuarioId], (err, usuario) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }

    if (!usuario) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }

    db.run("DELETE FROM USUARIO WHERE id = ?", [usuarioId], (err) => {
      if (err) {
        return res.status(500).json({ error: err.message });
      }

      res.json({
        message: "Usuário deletado com sucesso",
        usuarioDeletado: {
          id: usuario.id,
          email: usuario.email,
        },
      });
    });
  });
});

app.listen(PORT, () => {
  console.log(`
╔════════════════════════════════════════════════════════╗
║        Ekklesia Backend - Servidor iniciado            ║
╠════════════════════════════════════════════════════════╣
║  🚀 Servidor rodando em: http://localhost:${PORT}     ║
║  📁 Banco de dados: db/ekklesia.db                     ║
║                                                        ║
║  Endpoints de Autenticação:                            ║
║  POST   /api/auth/registro                             ║
║  POST   /api/auth/login                                ║
║  GET    /api/me (requer token)                         ║
║                                                        ║
║  Endpoints de Admin:                                   ║
║  DELETE /api/admin/usuarios/:id (requer admin)         ║
╚════════════════════════════════════════════════════════╝
  `);
});

module.exports = app;
