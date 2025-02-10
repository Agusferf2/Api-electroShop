# 🛒 API Electro-Shop

Esta es una API REST fake creada con `json-server` para el proyecto *Electro-Shop*, una tienda de productos electrónicos.
🔗 **Proyecto desplegado:** [Electro-Shop](https://electro-shop-puce.vercel.app/)  
🔗 **Repositorio en GitHub:** [ElectroShop](https://github.com/Agusferf2/Electro-Shop)  


## 🚀 Tecnologías utilizadas

- **Node.js** con `json-server`
- **Deploy en Render**
- **Base de datos en JSON (`db.json`)**

## 🌐 Endpoints disponibles

| Método  | Endpoint           | Descripción                              |
|---------|--------------------|------------------------------------------|
| GET     | `/products`        | Obtiene todos los productos              |
| GET     | `/products/:id`    | Obtiene un producto por ID               |
| POST    | `/products`        | Agrega un nuevo producto                 |
| PUT     | `/products/:id`    | Actualiza un producto existente          |
| DELETE  | `/products/:id`    | Elimina un producto                      |

🌍 API en producción

La API está desplegada en Render y disponible en:
https://api-electro-shop.onrender.com

Prueba los endpoints, por ejemplo:
https://api-electro-shop.onrender.com/products
