const sidebar = document.querySelector(".sidebar");
const toggleMenuContainer = document.querySelector(".menu-hamburguesa-container");

toggleMenuContainer.addEventListener("click", () => {
    sidebar.classList.toggle("open"); // Alterna la clase "open" en el sidebar
});

function toggleSubMenu() {
  var submenu = document.getElementById('submenu-polizas');
  submenu.style.display = submenu.style.display === 'block' ? 'none' : 'block';
}

function toggleDropdown() {
  document.getElementById("dropdown-menu").classList.toggle("show");
}

window.onclick = function(event) {
  if (!event.target.matches('.menu-button img')) {
      var dropdowns = document.getElementsByClassName("dropdown-content");
      for (var i = 0; i < dropdowns.length; i++) {
          var openDropdown = dropdowns[i];
          if (openDropdown.classList.contains('show')) {
              openDropdown.classList.remove('show');
          }
      }
  }
}

// Los valores de 10 minutos (600,000 ms) y 9 minutos son correctos.
let sessionTimeout = 15 * 60 * 1000;      // 15 minutos
let warningTime = sessionTimeout - (2 * 60 * 1000); // aviso 2 minutos antes
let sessionExpired = false;
let warningTimeout, sessionEndTimeout;

// *** Funciones de Manejo del Modal y Fin de Sesión ***
function showWarningModal() {
    if (!sessionExpired) {
        // Asegúrate de que el modal se muestre
        document.getElementById('session-expired-modal').style.display = 'flex';
    }
}

function logout() {
    sessionExpired = true; // Establecer el estado ANTES de redirigir
    window.location.href = '/logout';
}

function endSession() {
    // Si llegamos aquí, se cerrará la sesión sin importar si el modal está visible
    logout();
}

// *** Lógica de Temporizadores y Reinicio ***

// 1. Iniciar temporizadores
function startSessionTimers() {
    // Limpiamos por si acaso, aunque resetSessionTimers debería manejarlo
    clearTimeout(warningTimeout);
    clearTimeout(sessionEndTimeout);

    warningTimeout = setTimeout(showWarningModal, warningTime);
    sessionEndTimeout = setTimeout(endSession, sessionTimeout);
    console.log("Temporizadores iniciados/reiniciados.");
}

// 2. Función clave de reinicio (activada por interacción)
function resetSessionTimers() {
    if (!sessionExpired) {
        // Si hay actividad, reiniciamos el conteo
        startSessionTimers();
    }
}

// 3. Función de extensión de sesión (activada por botón)
function extendSession() {
    // Ocultar el modal inmediatamente para una experiencia de usuario rápida
    document.getElementById('session-expired-modal').style.display = 'none';

    fetch('/extend_session')
        .then(response => {
            // Manejo de errores de red o servidor más robusto
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            if (data.status === 'Session extended') {
                sessionExpired = false;
                // El reinicio de los temporizadores es lo más importante
                startSessionTimers();
            } else {
                console.error("Error al extender sesión:", data);
            }
        })
        .catch(error => {
            console.error('Error en la extensión de la sesión:', error);
            // Mostrar un mensaje de error al usuario, o forzar logout si falla
        });
}


function attachActivityListeners() {

    window.addEventListener('click', resetSessionTimers);

    window.addEventListener('keydown', resetSessionTimers);

    window.addEventListener('scroll', resetSessionTimers);

    window.addEventListener('touchstart', resetSessionTimers);

    window.addEventListener('mousemove', throttledMouseMove);

}

let lastMouseMove = 0;

function throttledMouseMove() {

    const now = Date.now();

    if (now - lastMouseMove > 5000) {
        lastMouseMove = now;
        resetSessionTimers();
    }

}

// *** Punto de Entrada Único (Garantiza el inicio) ***
document.addEventListener('DOMContentLoaded', () => {
    startSessionTimers();
    attachActivityListeners();
});
