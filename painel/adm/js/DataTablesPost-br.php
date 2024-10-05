<script type='text/javascript'> 
$('#Tabela').DataTable({
		"fnDrawCallback": function ( oSettings ) {
  			$("[data-toggle=popover]").popover();
            $(".popover-dismiss").popover({trigger: 'focus', html: true});
			$('.testeasdasd').css('height', 'auto');
		},
			<?php if(!empty($DataTablesTargets)) echo "\"columnDefs\": [".$DataTablesTargets."],"; ?>
			"serverSide": true,
			"ajax":{
					<?php if(empty($DataTablesP)) $DataTablesP = ""; ?>
					url: "<?php echo $DataTablesPost; ?>.php<?php echo $DataTablesP; ?>",
					type: "post",
					},
    "language": {
    "sEmptyTable": "Nenhum registro encontrado",
    "sInfo": "Mostrando de _START_ até _END_ de _TOTAL_ registros",
    "sInfoEmpty": "Mostrando 0 até 0 de 0 registros",
    "sInfoFiltered": "(Filtrados de _MAX_ registros)",
    "sInfoPostFix": "",
    "sInfoThousands": ".",
    "sLengthMenu": "_MENU_ resultados por página",
    "sLoadingRecords": "Carregando...",
    "sProcessing": "Processando...",
    "sZeroRecords": "Nenhum registro encontrado",
    "sSearch": "Pesquisar",
    "oPaginate": {
        "sNext": "Próximo",
        "sPrevious": "Anterior",
        "sFirst": "Primeiro",
        "sLast": "Último"
    },
    "oAria": {
        "sSortAscending": ": Ordenar colunas de forma ascendente",
        "sSortDescending": ": Ordenar colunas de forma descendente"
    }
}
});
</script>