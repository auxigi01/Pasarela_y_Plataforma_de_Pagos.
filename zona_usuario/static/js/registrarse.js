
var ver = document.getElementById('ver');
var input = document.getElementById('password');
ver.addEventListener("click", function(){
    if(input.type =="password"){
        input.type = "text"
        ver.classList.add('ver-visible');
        }
        else{
            input.type = "password"
            ver.classList.remove('ver-visible');
        }
})

var ver2 = document.getElementById('ver2');
var input2 = document.getElementById('confirm_password');
ver2.addEventListener("click", function(){
    if(input2.type =="password"){
        input2.type = "text"
        ver2.classList.add('ver-visible');
        }
        else{
            input2.type = "password"
            ver2.classList.remove('ver-visible');
        }
})
document.addEventListener('DOMContentLoaded', function() {
    const passwordField = document.getElementById('password');
    const confirmPasswordField = document.getElementById('confirm_password');
    const passwordHelp = document.getElementById('passwordHelp');
    const matchHelp = document.getElementById('matchHelp');

    // Mostrar u ocultar el mensaje de ayuda para la contraseña
    passwordField.addEventListener('input', function() {
        const passwordLength = passwordField.value.length;

        // Si el campo está vacío, oculta el mensaje
        if (passwordLength === 0) {
            passwordHelp.style.display = 'none';
            passwordHelp.style.color = '#6c757d'; // Color por defecto (gris claro)
        } else {
            // Si la longitud es menor a 8, el mensaje será rojo
            if (passwordLength < 8) {
                passwordHelp.style.display = 'block';
                passwordHelp.style.color = 'red';
            } else {
                // Si cumple con el mínimo, oculta el mensaje
                passwordHelp.style.display = 'none';
            }
        }
    });

    // Validar si las contraseñas coinciden
    function validatePasswordsMatch() {
        if (passwordField.value !== confirmPasswordField.value && confirmPasswordField.value !== "") {
            matchHelp.style.display = 'block';
            matchHelp.style.color = 'red';
        } else {
            matchHelp.style.display = 'none';
        }
    }

    confirmPasswordField.addEventListener('input', validatePasswordsMatch);
});