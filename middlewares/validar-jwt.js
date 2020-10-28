const jwt = require('jsonwebtoken');
const Usuario = require('../models/usuario');

const validarJWT = (req, res, next) => {

    // Leer el Token
    const token = req.header('x-token');

    if ( !token ) {
        return res.status(401).json({
            ok: false,
            msg: 'No hay token en la petición'
        });
    }

    try {
        
        const { uid } = jwt.verify( token, process.env.JWT_SECRET );
        req.uid = uid; //se establece aca

        next();

    } catch (error) {
        return res.status(401).json({
            ok: false,
            msg: 'Token no válido'
        });
    }
 
}

const validarADMIN_ROLE = async(req, res, next) => {

    const uid = req.uid;
    try {
        
        const usuarioDB = await Usuario.findById(uid);
        if(!usuarioDB){
            res.status(404).json({
                ok: false,
                msg: 'Usuario no existe'
            })
        }

        if(usuarioDB.role !== 'ADMIN_ROLE'){
            res.status(403).json({
                ok: false,
                msg: 'No tiene previlegios'
            })
        }

        next();

    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Hable con el administrador'
        })
    }
}

module.exports = {
    validarJWT,
    validarADMIN_ROLE
}