const sqlite3 = require("sqlite3").verbose();
const path = require("path");
const bcrypt = require("bcryptjs");

const DB_PATH = path.join(__dirname, "../db/ekklesia.db");

const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error("Erro ao conectar ao banco de dados:", err.message);
  } else {
    console.log("Conectado ao SQLite em:", DB_PATH);
    initializeDatabase();
  }
});

function initializeDatabase() {
  db.serialize(() => {
    db.run(
      `CREATE TABLE IF NOT EXISTS USUARIO (
        id INTEGER PRIMARY KEY,
        nome VARCHAR(120) NOT NULL,
        email VARCHAR(150) NOT NULL UNIQUE,
        senha_hash VARCHAR(255) NOT NULL,
        tipo_usuario VARCHAR(20) DEFAULT'USUARIO',
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        atualizado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`,
      (err) => {
        if (err) console.error("Erro ao criar tabela USUARIO:", err.message);
        else console.log("Tabela USUARIO verificada/criada");
      },
    );

    db.run(
      `CREATE TABLE IF NOT EXISTS MINISTERIO (
        id INTEGER PRIMARY KEY,
        nome VARCHAR(100) NOT NULL UNIQUE,
        descricao TEXT NULL,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`,
      (err) => {
        if (err) console.error("Erro ao criar tabela MINISTERIO:", err.message);
        else console.log("Tabela MINISTERIO verificada/criada");
      },
    );

    db.run(
      `CREATE TABLE IF NOT EXISTS USUARIO_MINISTERIO (
        id INTEGER PRIMARY KEY,
        usuario_id INTEGER NOT NULL,
        ministerio_id INTEGER NOT NULL,
        papel VARCHAR(20) NOT NULL,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (usuario_id, ministerio_id),
        FOREIGN KEY (usuario_id) REFERENCES USUARIO(id),
        FOREIGN KEY (ministerio_id) REFERENCES MINISTERIO(id)
      )`,
      (err) => {
        if (err) console.error("Erro ao criar tabela USUARIO_MINISTERIO:", err.message);
        else console.log("Tabela USUARIO_MINISTERIO verificada/criada");
      },
    );

    db.run(
      `CREATE TABLE IF NOT EXISTS EVENTO (
        id INTEGER PRIMARY KEY,
        titulo VARCHAR(150) NOT NULL,
        descricao TEXT NULL,
        local VARCHAR(150) NULL,
        inicio_em TIMESTAMP NOT NULL,
        fim_em TIMESTAMP NOT NULL,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )`,
      (err) => {
        if (err) console.error("Erro ao criar tabela EVENTO:", err.message);
        else console.log("Tabela EVENTO verificada/criada");
      },
    );

    db.run(
      `CREATE TABLE IF NOT EXISTS ESCALA (
        id INTEGER PRIMARY KEY,
        evento_id INTEGER NOT NULL,
        ministerio_id INTEGER NOT NULL,
        nome VARCHAR(120) NOT NULL,
        inicio_em TIMESTAMP NOT NULL,
        fim_em TIMESTAMP NOT NULL,
        observacoes TEXT NULL,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (evento_id) REFERENCES EVENTO(id),
        FOREIGN KEY (ministerio_id) REFERENCES MINISTERIO(id)
      )`,
      (err) => {
        if (err) console.error("Erro ao criar tabela ESCALA:", err.message);
        else console.log("Tabela ESCALA verificada/criada");
      },
    );

    db.run(
      `CREATE TABLE IF NOT EXISTS ESCALA_PARTICIPANTE (
        id INTEGER PRIMARY KEY,
        escala_id INTEGER NOT NULL,
        usuario_id INTEGER NOT NULL,
        funcao_id INTEGER NULL,
        status_convite VARCHAR(20) NOT NULL DEFAULT'PENDENTE',
        observacao TEXT NULL,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (escala_id, usuario_id),
        FOREIGN KEY (escala_id) REFERENCES ESCALA(id),
        FOREIGN KEY (usuario_id) REFERENCES USUARIO(id)
      )`,
      (err) => {
        if (err) console.error("Erro ao criar tabela ESCALA_PARTICIPANTE:", err.message);
        else console.log("Tabela ESCALA_PARTICIPANTE verificada/criada");
      },
    );

    setTimeout(async () => {
      await criarSuperAdmin();
    }, 1000);
  });
}

function criarSuperAdmin() {
  return new Promise((resolve) => {
    const email = "admin@ekklesia.com";
    const senhaPlana = "admin123";
    const nome = "Super Admin";

    db.get("SELECT * FROM USUARIO WHERE email = ?", [email], async (err, row) => {
      if (row) {
        console.log("✓ Super Admin já existe!");
        resolve();
        return;
      }

      try {
        const senhaHash = await bcrypt.hash(senhaPlana, 10);

        db.run("INSERT INTO USUARIO (nome, email, senha_hash, tipo_usuario) VALUES (?, ?, ?, ?)", [nome, email, senhaHash, "ADMIN"], (err) => {
          if (!err) {
            console.log(`✓ Super Admin criado!`);
            console.log(`   Email: ${email}`);
            console.log(`   Senha: ${senhaPlana}`);
          } else {
            console.error("Erro ao criar Super Admin:", err.message);
          }
          resolve();
        });
      } catch (error) {
        console.error("Erro ao hashear senha:", error.message);
        resolve();
      }
    });
  });
}

module.exports = db;
