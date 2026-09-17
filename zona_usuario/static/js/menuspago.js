// Desplazamiento de formularios
const headers = document.querySelectorAll('.header2');

headers.forEach(header => {
    header.addEventListener('click', () => {
        const content = header.nextElementSibling;

        const isOpen = content.classList.contains('show');

        // Cerrar todos los contenidos
        headers.forEach(h => {
            const otherContent = h.nextElementSibling;
            otherContent.classList.remove('show'); 
            otherContent.style.display = 'none'; 
        });

        if (!isOpen) {
            content.style.display = 'block'; 
            setTimeout(() => {
                content.classList.add('show'); 
            }, 10); 
        } else {
            content.classList.remove('show'); 
            setTimeout(() => {
                content.style.display = 'none'; 
            }, 500); 
        }
    });
});

