document.querySelectorAll('.clickable-row').forEach(row => {
    row.addEventListener('click', function() {
        document.getElementById('contratoInput').value = this.getAttribute('data-contrato');
        document.getElementById('companiaInput').value = this.getAttribute('data-compania');
        document.getElementById('monedaInput').value = this.getAttribute('data-moneda');
        document.getElementById('contratoForm').submit();
    });
});



