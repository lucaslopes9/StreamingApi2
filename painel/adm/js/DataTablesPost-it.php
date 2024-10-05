<script type='text/javascript'> 
$('#Tabela').DataTable({
	"fnDrawCallback": function ( oSettings ) {
  			$("[data-toggle=popover]").popover();
            $(".popover-dismiss").popover({trigger: 'focus', html: true});
	},
			<?php if(!empty($DataTablesTargets)) echo "\"columnDefs\": [".$DataTablesTargets."],"; ?>
			"serverSide": true,
			"ajax":{
					<?php if(empty($DataTablesP)) $DataTablesP = ""; ?>
					url: "<?php echo $DataTablesPost; ?>.php<?php echo $DataTablesP; ?>",
					type: "post",
					},
    "language": {
    "sEmptyTable":     "Nessun dato presente nella tabella",
    "sInfo":           "Vista da _START_ a _END_ di _TOTAL_ elementi",
    "sInfoEmpty":      "Vista da 0 a 0 di 0 elementi",
    "sInfoFiltered":   "(filtrati da _MAX_ elementi totali)",
    "sInfoPostFix":    "",
    "sInfoThousands":  ".",
    "sLengthMenu":     "Visualizza _MENU_ elementi",
    "sLoadingRecords": "Caricamento...",
    "sProcessing":     "Elaborazione...",
    "sSearch":         "Cerca:",
    "sZeroRecords":    "La ricerca non ha portato alcun risultato.",
    "oPaginate": {
        "sFirst":      "Inizio",
        "sPrevious":   "Precedente",
        "sNext":       "Successivo",
        "sLast":       "Fine"
    },
    "oAria": {
        "sSortAscending":  ": attiva per ordinare la colonna in ordine crescente",
        "sSortDescending": ": attiva per ordinare la colonna in ordine decrescente"
    }
}
});
</script>