const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const db = require("./database");

const app = express();
const PORT = 3000;
const JWT_SECRET = "seu_super_secret_key_aqui";

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
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

app.get("/api/usuarios", verificarToken, verificarAdminOuLider, (req, res) => {
  db.all("SELECT id, nome, email, tipo_usuario FROM USUARIO ORDER BY nome", [], (err, usuarios) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(usuarios);
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

  db.run("INSERT INTO EVENTO (titulo, descricao, local, inicio_em, fim_em) VALUES (?, ?, ?, ?, ?)", [titulo, descricao || null, local || null, inicio_em, fim_em], function (err) {
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
  });
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

  db.run("UPDATE EVENTO SET titulo = ?, descricao = ?, local = ?, inicio_em = ?, fim_em = ?, criado_em = CURRENT_TIMESTAMP WHERE id = ?", [titulo, descricao || null, local || null, inicio_em, fim_em, req.params.id], function (err) {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (this.changes === 0) {
      return res.status(404).json({ error: "Evento não encontrado" });
    }
    res.json({ message: "Evento atualizado com sucesso" });
  });
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

  if (!evento_id || !nome || !inicio_em || !fim_em) {
    return res.status(400).json({ error: "evento_id, nome, inicio_em e fim_em são obrigatórios" });
  }

  db.get("SELECT inicio_em, fim_em FROM EVENTO WHERE id = ?", [evento_id], (err, evento) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!evento) return res.status(404).json({ error: "Evento não encontrado" });

    if (new Date(inicio_em) < new Date(evento.inicio_em) || new Date(fim_em) > new Date(evento.fim_em)) {
      return res.status(400).json({ error: "A escala deve estar dentro do período do evento" });
    }

    db.run(
      "INSERT INTO ESCALA (evento_id, ministerio_id, nome, inicio_em, fim_em, observacoes, criado_por) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [evento_id, ministerio_id, nome, inicio_em, fim_em, observacoes || null, req.usuario.id],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.status(201).json({ id: this.lastID, evento_id, ministerio_id, nome, inicio_em, fim_em, observacoes, criado_por: req.usuario.id, message: "Escala criada com sucesso" });
      },
    );
  });
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
      ep.horario_inicio,
      ep.horario_fim,
      u.nome,
      u.email
    FROM ESCALA_PARTICIPANTE ep
    JOIN USUARIO u ON ep.usuario_id = u.id
    WHERE ep.escala_id = ?
    ORDER BY CASE WHEN ep.horario_inicio IS NULL THEN 1 ELSE 0 END, ep.horario_inicio ASC, u.nome ASC
  `;

  db.all(query, [req.params.id], (err, participantes) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    res.json(participantes);
  });
});

app.post("/api/escalas/:id/participantes", verificarToken, verificarAdminOuLider, (req, res) => {
  const { usuario_id, funcao_id, observacao, horario_inicio, horario_fim } = req.body;
  const escala_id = req.params.id;

  if (!usuario_id) {
    return res.status(400).json({ error: "usuario_id é obrigatório" });
  }

  if (!horario_inicio || !horario_fim) {
    return res.status(400).json({ error: "Horário de início e fim são obrigatórios" });
  }

  if (new Date(horario_fim) <= new Date(horario_inicio)) {
    return res.status(400).json({ error: "O horário de fim deve ser posterior ao horário de início" });
  }

  // US6 CA2 - check for time conflict with other escalas
  db.get("SELECT id, nome, inicio_em, fim_em FROM ESCALA WHERE id = ?", [escala_id], (err, escala) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!escala) return res.status(404).json({ error: "Escala não encontrada" });

    if (horario_inicio && new Date(horario_inicio) < new Date(escala.inicio_em)) {
      return res.status(400).json({ error: "O horário de início do participante não pode ser anterior ao início da escala" });
    }
    if (horario_fim && new Date(horario_fim) > new Date(escala.fim_em)) {
      return res.status(400).json({ error: "O horário de fim do participante não pode ser posterior ao fim da escala" });
    }

    const conflictQuery = `
      SELECT e.nome FROM ESCALA_PARTICIPANTE ep
      JOIN ESCALA e ON ep.escala_id = e.id
      WHERE ep.usuario_id = ? AND ep.escala_id != ?
        AND e.inicio_em < ? AND e.fim_em > ?
      LIMIT 1
    `;
    db.get(conflictQuery, [usuario_id, escala_id, escala.fim_em, escala.inicio_em], (err, conflict) => {
      if (err) return res.status(500).json({ error: err.message });
      if (conflict) {
        return res.status(400).json({ error: `Conflito de horário: usuário já está na escala "${conflict.nome}" neste período` });
      }

      db.run(
        "INSERT INTO ESCALA_PARTICIPANTE (escala_id, usuario_id, funcao_id, observacao, status_convite, horario_inicio, horario_fim, adicionado_por) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [escala_id, usuario_id, funcao_id || null, observacao || null, "PENDENTE", horario_inicio || null, horario_fim || null, req.usuario.id],
        function (err) {
          if (err) {
            if (err.message.includes("UNIQUE")) {
              return res.status(400).json({ error: "Usuário já adicionado a esta escala" });
            }
            return res.status(500).json({ error: err.message });
          }
          const participanteId = this.lastID;
          const funcaoStr = funcao_id ? ` como ${funcao_id}` : "";
          const fmtDate = (iso) => {
            const d = new Date(iso);
            return d.toLocaleString("pt-BR", { day: "2-digit", month: "2-digit", year: "numeric", hour: "2-digit", minute: "2-digit" });
          };
          const periodoStr = `de ${fmtDate(escala.inicio_em)} até ${fmtDate(escala.fim_em)}`;
          const titulo = `Você foi escalado: ${escala.nome}`;
          const descricao = `Você foi adicionado à escala "${escala.nome}"${funcaoStr} (${periodoStr}). Confirme ou recuse sua participação.`;
          db.run("INSERT INTO NOTIFICACAO (usuario_id, titulo, descricao, escala_id, participante_id) VALUES (?, ?, ?, ?, ?)", [usuario_id, titulo, descricao, escala_id, participanteId], () => {});
          res.status(201).json({
            id: participanteId,
            escala_id,
            usuario_id,
            funcao_id,
            observacao,
            horario_inicio,
            horario_fim,
            status_convite: "PENDENTE",
            message: "Participante adicionado com sucesso",
          });
        },
      );
    });
  });
});

app.put("/api/escalas/:id", verificarToken, verificarAdminOuLider, (req, res) => {
  const { nome, inicio_em, fim_em, observacoes } = req.body;

  if (!nome || !inicio_em || !fim_em) {
    return res.status(400).json({ error: "Nome, início e fim são obrigatórios" });
  }

  db.get("SELECT evento_id FROM ESCALA WHERE id = ?", [req.params.id], (err, escala) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!escala) return res.status(404).json({ error: "Escala não encontrada" });

    db.get("SELECT inicio_em, fim_em FROM EVENTO WHERE id = ?", [escala.evento_id], (err, evento) => {
      if (err) return res.status(500).json({ error: err.message });
      if (evento && (new Date(inicio_em) < new Date(evento.inicio_em) || new Date(fim_em) > new Date(evento.fim_em))) {
        return res.status(400).json({ error: "A escala deve estar dentro do período do evento" });
      }

      db.run("UPDATE ESCALA SET nome = ?, inicio_em = ?, fim_em = ?, observacoes = ? WHERE id = ?", [nome, inicio_em, fim_em, observacoes || null, req.params.id], function (err) {
        if (err) return res.status(500).json({ error: err.message });
        if (this.changes === 0) return res.status(404).json({ error: "Escala não encontrada" });
        res.json({ message: "Escala atualizada com sucesso" });
      });
    });
  });
});

app.put("/api/escalas/participantes/:id", verificarToken, (req, res) => {
  const { status_convite, observacao, horario_inicio, horario_fim } = req.body;

  if (!status_convite) {
    return res.status(400).json({ error: "status_convite é obrigatório" });
  }

  db.get(
    `SELECT ep.usuario_id, ep.escala_id, ep.adicionado_por, u.nome as participante_nome, e.nome as escala_nome, e.criado_por
     FROM ESCALA_PARTICIPANTE ep
     JOIN USUARIO u ON ep.usuario_id = u.id
     JOIN ESCALA e ON ep.escala_id = e.id
     WHERE ep.id = ?`,
    [req.params.id],
    (err, row) => {
      if (err) return res.status(500).json({ error: err.message });
      if (!row) return res.status(404).json({ error: "Participante não encontrado" });

      db.run(
        "UPDATE ESCALA_PARTICIPANTE SET status_convite = ?, observacao = ?, horario_inicio = ?, horario_fim = ? WHERE id = ?",
        [status_convite, observacao || null, horario_inicio || null, horario_fim || null, req.params.id],
        function (err) {
          if (err) return res.status(500).json({ error: err.message });

          const notificar = row.criado_por || row.adicionado_por;
          if (notificar && notificar !== row.usuario_id) {
            const statusText = status_convite === "CONFIRMADO" ? "confirmou" : "recusou";
            const titulo = `${row.participante_nome} ${statusText} participação`;
            const descricao = `${row.participante_nome} ${statusText} a participação na escala "${row.escala_nome}".`;
            db.run("INSERT INTO NOTIFICACAO (usuario_id, titulo, descricao, escala_id) VALUES (?, ?, ?, ?)", [notificar, titulo, descricao, row.escala_id], () => {});
          }

          res.json({ message: "Status do participante atualizado com sucesso" });
        },
      );
    },
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

// ==================== NOTIFICAÇÕES ====================

app.get("/api/notificacoes", verificarToken, (req, res) => {
  db.all("SELECT * FROM NOTIFICACAO WHERE usuario_id = ? ORDER BY criado_em DESC", [req.usuario.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.get("/api/notificacoes/count", verificarToken, (req, res) => {
  db.get("SELECT COUNT(*) as count FROM NOTIFICACAO WHERE usuario_id = ? AND lida = 0", [req.usuario.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ count: row.count });
  });
});

app.put("/api/notificacoes/:id/lida", verificarToken, (req, res) => {
  db.run("UPDATE NOTIFICACAO SET lida = 1 WHERE id = ? AND usuario_id = ?", [req.params.id, req.usuario.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    if (this.changes === 0) return res.status(404).json({ error: "Notificação não encontrada" });
    res.json({ message: "Notificação marcada como lida" });
  });
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em: http://localhost:${PORT}`);
});

module.exports = app;
