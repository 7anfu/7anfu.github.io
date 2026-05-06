# 🛡️ Blog de Ciberseguridad — Jekyll + Chirpy

Blog técnico para writeups de CTFs, investigaciones y notas de Red Team.
Construido con [Jekyll](https://jekyllrb.com/) y el tema [Chirpy](https://github.com/cotes2020/jekyll-theme-chirpy).

---

## 🚀 Puesta en marcha

### Requisitos previos
- Ruby >= 3.1
- Bundler (`gem install bundler`)
- Git

### Instalación local

```bash
# 1. Clona / descarga este repo
git clone https://github.com/TODO_USUARIO/TODO_REPO.git
cd TODO_REPO

# 2. Instala dependencias
bundle install

# 3. Sirve el blog en local
bundle exec jekyll serve --livereload

# 4. Abre http://127.0.0.1:4000
```

### Build de producción

```bash
JEKYLL_ENV=production bundle exec jekyll build
```

---

## ✍️ Crear nuevos posts

Los posts viven en `_posts/` y siguen el formato:

```
YYYY-MM-DD-titulo-en-slug.md
```

### Plantillas disponibles

| Tipo                  | Archivo de ejemplo                                |
|-----------------------|---------------------------------------------------|
| Writeup CTF           | `_posts/2026-01-01-ejemplo-writeup-ctf.md`        |
| Investigación técnica | `_posts/2026-01-02-ejemplo-investigacion.md`      |
| Nota rápida           | `_posts/2026-01-03-ejemplo-nota-rapida.md`        |

Copia la plantilla que necesites, renombra el archivo y rellena el contenido.

### Frontmatter mínimo

```yaml
---
title: "Mi título"
date: 2026-01-01 12:00:00 +0100
categories: [CTF, HackTheBox]
tags: [web, linux]
description: "Resumen breve."
---
```

> 💡 Para drafts usa la carpeta `_drafts/` y sirve con:
> `bundle exec jekyll serve --drafts`

---

## 🎨 Personalizar el tema

| Elemento          | Dónde tocarlo                                  |
|-------------------|------------------------------------------------|
| Nombre / título   | `_config.yml` → `title`, `tagline`             |
| Avatar            | `assets/img/avatar.png` + `_config.yml`        |
| Redes sociales    | `_data/contact.yml` + `_config.yml` → `social` |
| Páginas del menú  | `_tabs/*.md` (campo `order`)                   |
| Comentarios       | `_config.yml` → bloque `comments`              |
| Analytics         | `_config.yml` → bloque `google_analytics`      |
| Tema claro/oscuro | `_config.yml` → `theme_mode`                   |

---

## 🚢 Despliegue en GitHub Pages

1. Crea un repo en GitHub (público o privado con Pages habilitado).
2. Push del proyecto a la rama `main`.
3. En **Settings → Pages**, selecciona **Source: GitHub Actions**.
4. El workflow `.github/workflows/pages-deploy.yml` se encarga del resto.

> Si publicas en `usuario.github.io/repo` recuerda fijar `baseurl: "/repo"` en `_config.yml`.

---

## 📂 Estructura del proyecto

```
mi-blog-ctf/
├── _config.yml              # Configuración principal
├── Gemfile                  # Dependencias Ruby
├── index.html               # Home (layout chirpy)
├── 404.html                 # Página de error
├── TAXONOMY.md              # Categorías y tags sugeridos
├── _data/
│   └── contact.yml          # Iconos sociales sidebar
├── _tabs/                   # Páginas del menú lateral
│   ├── about.md
│   ├── archives.md
│   ├── categories.md
│   ├── tags.md
│   └── contact.md
├── _posts/                  # Posts publicados
├── _drafts/                 # Borradores
├── assets/img/              # Imágenes (avatar, posts, favicons)
└── .github/workflows/
    └── pages-deploy.yml     # CI/CD GitHub Pages
```

---

## 🧠 Buenas prácticas para blogging técnico ofensivo

1. **Nunca publiques credenciales reales** ni IPs/usuarios reales en máquinas activas.
2. **Respeta las reglas de las plataformas** (HTB, THM): no publiques writeups de máquinas activas.
3. **Cita tus fuentes** (CVEs, papers, advisories, autores originales).
4. **Reproduce siempre tu PoC en lab propio** antes de publicarlo.
5. **Usa disclosure responsable** para vulnerabilidades 0-day.
6. **Mantén consistencia en categorías y tags** (ver `TAXONOMY.md`).
7. **Versiona tus payloads** en repos separados y enlázalos.
8. **Acompaña capturas con texto alt** (accesibilidad y SEO).
9. **Aplica `pin: true`** en tus posts más relevantes.
10. **Backups regulares**: el contenido es tu activo principal.

---

## 📜 Licencia

TODO: elige licencia (MIT / CC-BY-SA-4.0 / etc.)
