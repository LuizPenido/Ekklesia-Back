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

function verificarAdminOuLider(req, res, next) {
  if (req.usuario.tipo_usuario !== "ADMIN" && req.usuario.tipo_usuario !== "LIDER") {
    return res.status(403).json({ error: "Acesso negado. Apenas administradores e líderes podem executar esta ação" });
  }
  next();
}

app.post("/api/auth/registro", verificarToken, verificarAdminOuLider, async (req, res) => {
  try {
    const { nome, email, senha, tipo_usuario = "USUARIO" } = req.body;

    if (!nome || !email || !senha) {
      return res.status(400).json({ error: "Nome, email e senha são obrigatórios" });
    }

    db.get("SELECT * FROM USUARIO WHERE email = ?", [email], async (err, row) => {
      if (row) {
        return res.status(400).json({ error: "Email já cadastrado" });
      }

      try {
        const hash = await bcrypt.hash(senha, 10);

        db.run("INSERT INTO USUARIO (nome, email, senha_hash, tipo_usuario) VALUES (?, ?, ?, ?)", [nome, email, hash, tipo_usuario], function (err) {
          if (err) {
            return res.status(500).json({ error: err.message });
          }

          res.status(201).json({
            id: this.lastID,
            nome,
            email,
            tipo_usuario,
            message: "Usuário cadastrado com sucesso",
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

app.get("/api/admin/usuarios", verificarToken, verificarAdmin, (req, res) => {
  db.all("SELECT id, nome, email, tipo_usuario, criado_em FROM USUARIO ORDER BY criado_em DESC", [], (err, usuarios) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(usuarios);
  });
});

app.get("/api/admin/usuarios/:id", verificarToken, verificarAdmin, (req, res) => {
  db.get("SELECT id, nome, email, tipo_usuario, criado_em FROM USUARIO WHERE id = ?", [req.params.id], (err, usuario) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!usuario) {
      return res.status(404).json({ error: "Usuário não encontrado" });
    }
    res.json(usuario);
  });
});

app.put("/api/admin/usuarios/:id", verificarToken, verificarAdmin, async (req, res) => {
  const { nome, email, tipo_usuario } = req.body;
  const usuarioId = req.params.id;

  if (!nome || !email || !tipo_usuario) {
    return res.status(400).json({ error: "Nome, email e tipo de usuário são obrigatórios" });
  }

  db.get("SELECT email FROM USUARIO WHERE email = ? AND id != ?", [email, usuarioId], (err, row) => {
    if (row) {
      return res.status(400).json({ error: "Email já existe" });
    }

    db.run("UPDATE USUARIO SET nome = ?, email = ?, tipo_usuario = ?, atualizado_em = CURRENT_TIMESTAMP WHERE id = ?", [nome, email, tipo_usuario, usuarioId], function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: "Usuário não encontrado" });
      }
      res.json({ message: "Usuário atualizado com sucesso" });
    });
  });
});

app.post("/api/eventos", verificarToken, verificarAdminOuLider, (req, res) => {
  const { titulo, descricao, local, inicio_em, fim_em } = req.body;

  if (!titulo || !inicio_em || !fim_em) {
    return res.status(400).json({ error: "Título, início e fim são obrigatórios" });
  }

  db.run(
    "INSERT INTO EVENTO (titulo, descricao, local, inicio_em, fim_em) VALUES (?, ?, ?, ?, ?)",
    [titulo, descricao || null, local || null, inicio_em, fim_em],
    function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({
        id: this.lastID,
        titulo,
        descricao,
        local,
        inicio_em,
        fim_em,
        message: "Evento criado com sucesso",
      });
    }
  );
});

app.get("/api/eventos", verificarToken, (req, res) => {
  db.all("SELECT * FROM EVENTO ORDER BY inicio_em DESC", [], (err, eventos) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(eventos);
  });
});

app.get("/api/eventos/:id", verificarToken, (req, res) => {
  db.get("SELECT * FROM EVENTO WHERE id = ?", [req.params.id], (err, evento) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!evento) {
      return res.status(404).json({ error: "Evento não encontrado" });
    }
    res.json(evento);
  });
});

app.put("/api/eventos/:id", verificarToken, verificarAdminOuLider, (req, res) => {
  const { titulo, descricao, local, inicio_em, fim_em } = req.body;

  if (!titulo || !inicio_em || !fim_em) {
    return res.status(400).json({ error: "Título, início e fim são obrigatórios" });
  }

  db.run(
    "UPDATE EVENTO SET titulo = ?, descricao = ?, local = ?, inicio_em = ?, fim_em = ?, criado_em = CURRENT_TIMESTAMP WHERE id = ?",
    [titulo, descricao || null, local || null, inicio_em, fim_em, req.params.id],
    function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: "Evento não encontrado" });
      }
      res.json({ message: "Evento atualizado com sucesso" });
    }
  );
});

app.delete("/api/eventos/:id", verificarToken, verificarAdminOuLider, (req, res) => {
  db.run("DELETE FROM EVENTO WHERE id = ?", [req.params.id], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: "Evento não encontrado" });
    }
    res.json({ message: "Evento deletado com sucesso" });
  });
});

app.post("/api/escalas", verificarToken, verificarAdminOuLider, (req, res) => {
  const { evento_id, ministerio_id, nome, inicio_em, fim_em, observacoes } = req.body;

  db.run(
    "INSERT INTO ESCALA (evento_id, ministerio_id, nome, inicio_em, fim_em, observacoes) VALUES (?, ?, ?, ?, ?, ?)",
    [evento_id, ministerio_id, nome, inicio_em, fim_em, observacoes || null],
    function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({
        id: this.lastID,
        evento_id,
        ministerio_id,
        nome,
        inicio_em,
        fim_em,
        observacoes,
        message: "Escala criada com sucesso",
      });
    }
  );
});

app.get("/api/escalas", verificarToken, (req, res) => {
  db.all("SELECT * FROM ESCALA ORDER BY inicio_em DESC", [], (err, escalas) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(escalas);
  });
});

app.get("/api/escalas/:id", verificarToken, (req, res) => {
  db.get("SELECT * FROM ESCALA WHERE id = ?", [req.params.id], (err, escala) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (!escala) {
      return res.status(404).json({ error: "Escala não encontrada" });
    }
    res.json(escala);
  });
});

app.get("/api/escalas/:id/participantes", verificarToken, (req, res) => {
  const query = `
    SELECT 
      ep.id,
      ep.escala_id,
      ep.usuario_id,
      ep.funcao_id,
      ep.status_convite,
      ep.observacao,
      u.nome,
      u.email
    FROM ESCALA_PARTICIPANTE ep
    JOIN USUARIO u ON ep.usuario_id = u.id
    WHERE ep.escala_id = ?
    ORDER BY u.nome
  `;

  db.all(query, [req.params.id], (err, participantes) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(participantes);
  });
});

app.post("/api/escalas/:id/participantes", verificarToken, verificarAdminOuLider, (req, res) => {
  const { usuario_id, funcao_id, observacao } = req.body;
  const escala_id = req.params.id;

  if (!usuario_id) {
    return res.status(400).json({ error: "usuario_id é obrigatório" });
  }

  db.run(
    "INSERT INTO ESCALA_PARTICIPANTE (escala_id, usuario_id, funcao_id, observacao, status_convite) VALUES (?, ?, ?, ?, ?)",
    [escala_id, usuario_id, funcao_id || null, observacao || null, "PENDENTE"],
    function (err) {
      if (err) {
        if (err.message.includes("UNIQUE")) {
          return res.status(400).json({ error: "Usuário já adicionado a esta escala" });
        }
        return res.status(500).json({ error: err.message });
      }
      res.status(201).json({
        id: this.lastID,
        escala_id,
        usuario_id,
        funcao_id,
        observacao,
        status_convite: "PENDENTE",
        message: "Participante adicionado com sucesso",
      });
    }
  );
});

app.put("/api/escalas/:id", verificarToken, verificarAdminOuLider, (req, res) => {
  const { nome, inicio_em, fim_em, observacoes } = req.body;

  if (!nome || !inicio_em || !fim_em) {
    return res.status(400).json({ error: "Nome, início e fim são obrigatórios" });
  }

  db.run(
    "UPDATE ESCALA SET nome = ?, inicio_em = ?, fim_em = ?, observacoes = ? WHERE id = ?",
    [nome, inicio_em, fim_em, observacoes || null, req.params.id],
    function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: "Escala não encontrada" });
      }
      res.json({ message: "Escala atualizada com sucesso" });
    }
  );
});

app.put("/api/escalas/participantes/:id", verificarToken, (req, res) => {
  const { status_convite, observacao } = req.body;

  if (!status_convite) {
    return res.status(400).json({ error: "status_convite é obrigatório" });
  }

  db.run(
    "UPDATE ESCALA_PARTICIPANTE SET status_convite = ?, observacao = ? WHERE id = ?",
    [status_convite, observacao || null, req.params.id],
    function (err) {
      if (err) {
        return res.status(500).json({ error: err.message });
      }
      if (this.changes === 0) {
        return res.status(404).json({ error: "Participante não encontrado" });
      }
      res.json({ message: "Status do participante atualizado com sucesso" });
    }
  );
});

app.delete("/api/escalas/:id", verificarToken, verificarAdminOuLider, (req, res) => {
  db.run("DELETE FROM ESCALA WHERE id = ?", [req.params.id], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: "Escala não encontrada" });
    }
    res.json({ message: "Escala deletada com sucesso" });
  });
});

app.delete("/api/escalas/participantes/:id", verificarToken, verificarAdminOuLider, (req, res) => {
  db.run("DELETE FROM ESCALA_PARTICIPANTE WHERE id = ?", [req.params.id], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: "Participante não encontrado" });
    }
    res.json({ message: "Participante removido com sucesso" });
  });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em: http://localhost:${PORT}`);
});

module.exports = app;
