const csrfToken = document
    .querySelector('meta[name="csrf-token"]')
    .getAttribute('content');


document.addEventListener('DOMContentLoaded', function(event) {
    var selectAllCheckbox = document.getElementById('select-all');
    var rowCheckboxes = document.querySelectorAll('.row-checkbox');
    var rows = document.querySelectorAll('tbody tr');
    var totalMontoElement = document.getElementById('totalbs');
    var totalUsdElement = document.getElementById('totalusd');

    function updateSelectAllCheckbox() {
        var allChecked = true;
        rowCheckboxes.forEach(function(checkbox) {
            if (!checkbox.checked && !checkbox.disabled) {
                allChecked = false;
            }
        });
        selectAllCheckbox.checked = allChecked;
    }

    function checkPreviousCheckboxes(index) {
        for (var i = 0; i <= index; i++) {
            if (!rowCheckboxes[i].disabled) {
                if (!rowCheckboxes[i].checked) {
                    rowCheckboxes[i].checked = true;
                    updateTotalMonto();
                }
            }
        }
    }

    function uncheckCheckboxesFrom(index) {
        for (var i = index; i < rowCheckboxes.length; i++) {
            if (!rowCheckboxes[i].disabled) {
                if (rowCheckboxes[i].checked) {
                    rowCheckboxes[i].checked = false;
                    updateTotalMonto();
                }
            }
        }
    }

    function parseCurrency(value) {
        if (typeof value === 'string') {
            value = value.replace(/\./g, '').replace(/,/g, '.');
        }
        return parseFloat(value);
    }

    function formatCurrency(value) {
        value = parseFloat(value).toFixed(2);
        return value.replace(/\B(?=(\d{3})+(?!\d))/g, '.').replace(/\.(?=\d{2}$)/, ',');
    }

    function updateTotalMonto() {
        var totalMonto = 0;
        var totalMontoUs = 0;

        rows.forEach(function(row) {
            var checkbox = row.querySelector('.row-checkbox');
            var montoCell = row.querySelector('.monto');
            var montoUsCell = row.querySelector('.montous');
            var monto = montoCell.textContent || montoCell.innerText;
            var montoUs = montoUsCell ? (montoUsCell.textContent || montoUsCell.innerText) : "0";

            var numericMonto = parseCurrency(monto);
            var numericMontoUs = parseCurrency(montoUs);

            if (checkbox.checked && !checkbox.disabled) {
                totalMonto += numericMonto;
                totalMontoUs += numericMontoUs;
            }
        });

        var formattedTotal = formatCurrency(totalMonto);
        var formattedUsd = formatCurrency(totalMontoUs);

        totalMontoElement.textContent = 'Pagar Total BS: ' + formattedTotal;
        totalUsdElement.textContent = 'Pagar Total USD: ' + formattedUsd;
    }

    selectAllCheckbox.addEventListener('change', function(event) {
        rowCheckboxes.forEach(function(checkbox) {
            if (!checkbox.disabled) {
                checkbox.checked = selectAllCheckbox.checked;
            }
        });
        updateTotalMonto();
        checkIfAnyCheckboxSelected();
    });

    rowCheckboxes.forEach(function(checkbox, index) {
        checkbox.addEventListener('change', function(event) {
            if (checkbox.checked) {
                checkPreviousCheckboxes(index);
            } else {
                uncheckCheckboxesFrom(index);
            }
            updateTotalMonto();
            updateSelectAllCheckbox();
        });
    });

    rows.forEach(function(row) {
        var statusCell = row.cells[2];
        var checkbox = row.querySelector('.row-checkbox');
        if (statusCell.textContent.trim().toLowerCase() === 'pagado') {
            checkbox.disabled = true;
        }
    });

    totalMontoElement.addEventListener('click', function() {
        var totalMonto = 0;
        var totalMontoUs = 0;
        var montoHelp = document.getElementById('montoHelp');
        var cuotasSeleccionadas = [];
        var fechasVctoSeleccionadas = [];
        var lista_montosbs = [];
        var lista_montosus = [];
        var idsCuotasSeleccionadas = [];
        var lista_tasas = [];

        var compania = document.getElementById('compania').value;
        var moneda = document.getElementById('moneda').value;

        rows.forEach(function(row) {
            var checkbox = row.querySelector('.row-checkbox');
            var montoCell = row.querySelector('.monto');
            var montoUsCell = row.querySelector('.montous');
            var cuotaCell = row.cells[1];
            var fechaVctoCell = row.cells[3];
            var idCuotaCell = row.cells[7];
            var tasaCell = row.cells[8];

            var monto = montoCell.textContent || montoCell.innerText;
            var montoUs = montoUsCell ? (montoUsCell.textContent || montoUsCell.innerText) : "0";
            var tasa = tasaCell ? (tasaCell.textContent || tasaCell.innerText) : "0";

            var numericMonto = parseCurrency(monto);
            var numericMontoUs = parseCurrency(montoUs);

            if (checkbox.checked && !checkbox.disabled) {
                totalMonto += numericMonto;
                totalMontoUs += numericMontoUs;
                cuotasSeleccionadas.push(cuotaCell.textContent.trim());
                fechasVctoSeleccionadas.push(fechaVctoCell.textContent.trim());
                lista_montosbs.push(monto.trim());
                lista_montosus.push(montoUs.trim());
                idsCuotasSeleccionadas.push(idCuotaCell.textContent.trim());
                lista_tasas.push(tasa.trim());
            }
        });

        if (totalMonto <= 0 || cuotasSeleccionadas.length === 0) {
            montoHelp.style.display = 'block';
            return;
        }

        montoHelp.style.display = 'none';

        var redirectUrl = '';
        if (compania === 'RMP') {
            redirectUrl = '/metodos_de_pago_bs';
        } else if (compania === 'AMB') {
            redirectUrl = '/metodos_de_pago_bs_amb';
        } else {
            alert('Error: Compañía o moneda no válida.');
            return;
        }

        fetch('/guardar_datos_pago', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({
                montobs: totalMonto.toFixed(2),
                cuotas: cuotasSeleccionadas,
                fechasvct: fechasVctoSeleccionadas,
                lista_montosbs: lista_montosbs,
                lista_montosus: lista_montosus,
                idcuotas: idsCuotasSeleccionadas,
                lista_tasas: lista_tasas,
                moneda_pago: 'Bs'
            })
        })
        .then(response => {

            if (!response.ok) {

                throw new Error("Error HTTP " + response.status);

            }

            return response.json();

        })
        .then(data => {
            if (data.success) {
                window.location.href = redirectUrl;
            } else {
                alert('Error al procesar los datos.');
            }
        })
        .catch(error => console.error('Error:', error));
    });

totalUsdElement.addEventListener('click', function() {
    var totalMonto = 0;
    var totalMontoUs = 0;
    var montoHelp = document.getElementById('montoHelp');
    var cuotasSeleccionadas = [];
    var fechasVctoSeleccionadas = [];
    var lista_montosbs = [];
    var lista_montosus = [];
    var idsCuotasSeleccionadas = [];
    var lista_tasas = [];

    var compania = document.getElementById('compania').value;

    rows.forEach(function(row) {
        var checkbox = row.querySelector('.row-checkbox');
        var montoCell = row.querySelector('.monto');
        var montoUsCell = row.querySelector('.montous');
        var cuotaCell = row.cells[1];
        var fechaVctoCell = row.cells[3];
        var idCuotaCell = row.cells[7];
        var tasaCell = row.cells[8];

        var monto = montoCell.textContent || montoCell.innerText;
        var montoUs = montoUsCell ? (montoUsCell.textContent || montoUsCell.innerText) : "0";
        var tasa = tasaCell ? (tasaCell.textContent || tasaCell.innerText) : "0";

        var numericMonto = parseCurrency(monto);
        var numericMontoUs = parseCurrency(montoUs);

        if (checkbox.checked && !checkbox.disabled) {
            totalMonto += numericMonto;
            totalMontoUs += numericMontoUs;
            cuotasSeleccionadas.push(cuotaCell.textContent.trim());
            fechasVctoSeleccionadas.push(fechaVctoCell.textContent.trim());
            lista_montosbs.push(monto.trim());
            lista_montosus.push(montoUs.trim());
            idsCuotasSeleccionadas.push(idCuotaCell.textContent.trim());
            lista_tasas.push(tasa.trim());
        }
    });

    if (totalMontoUs <= 0 || cuotasSeleccionadas.length === 0) {
        montoHelp.style.display = 'block';
        return;
    }

    montoHelp.style.display = 'none';

    var itf = totalMontoUs * 0.03;
    var totalConItf = totalMontoUs + itf;

    Swal.fire({
        title: 'Confirmar pago en USD',
        html: `
            <p>Para pagar en dólares se aplicará un <strong>ITF del 3%</strong>.</p>
            <p><strong>Total actual:</strong> $${totalMontoUs.toFixed(2)}</p>
            <p><strong>ITF (3%):</strong> $${itf.toFixed(2)}</p>
            <p><strong>Total con ITF:</strong> $${totalConItf.toFixed(2)}</p>
        `,
        icon: 'warning',
        showCancelButton: true,
        confirmButtonText: 'Sí, aceptar',
        cancelButtonText: 'Cancelar',
        confirmButtonColor: '#03519E',
        cancelButtonColor: '#D9251D',
    }).then((result) => {
        if (result.isConfirmed) {
            var redirectUrl = '';
            if (compania === 'RMP') {
                redirectUrl = '/metodos_de_pago_usd';
            } else if (compania === 'AMB') {
                redirectUrl = '/metodos_de_pago_usd_amb';
            } else {
                Swal.fire('Error', 'Compañía o moneda no válida.', 'error');
                return;
            }

            fetch('/guardar_datos_pago', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({
                    montous: totalConItf.toFixed(2),
                    cuotas: cuotasSeleccionadas,
                    fechasvct: fechasVctoSeleccionadas,
                    lista_montosbs: lista_montosbs,
                    lista_montosus: lista_montosus,
                    idcuotas: idsCuotasSeleccionadas,
                    lista_tasas: lista_tasas,
                    moneda_pago: 'Us'
                })
            })
            .then(response => {

            if (!response.ok) {

                throw new Error("Error HTTP " + response.status);

            }

            return response.json();

        })
            .then(data => {
                if (data.success) {
                    window.location.href = redirectUrl;
                } else {
                    Swal.fire('Error', 'Hubo un problema al procesar el pago.', 'error');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                Swal.fire('Error', 'No se pudo enviar la solicitud.', 'error');
            });
        }
    });
});

    function checkIfAnyCheckboxSelected() {
        var anyChecked = false;
        var montoHelp = document.getElementById('montoHelp');

        rows.forEach(function(row) {
            var checkbox = row.querySelector('.row-checkbox');
            if (checkbox.checked && !checkbox.disabled) {
                anyChecked = true;
            }
        });

        if (anyChecked) {
            montoHelp.style.display = 'none';
        }
    }

    rows.forEach(function(row) {
        var checkbox = row.querySelector('.row-checkbox');
        checkbox.addEventListener('change', checkIfAnyCheckboxSelected);
    });

    checkIfAnyCheckboxSelected();

    totalMontoElement.textContent = 'Pagar Total BS: 0,00';
    totalUsdElement.textContent = 'Pagar Total USD: 0,00';
});
