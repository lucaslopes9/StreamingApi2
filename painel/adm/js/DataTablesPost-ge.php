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
    "sEmptyTable":      "Keine Daten in der Tabelle vorhanden",
    "sInfo":            "_START_ bis _END_ von _TOTAL_ Einträgen",
    "sInfoEmpty":       "0 bis 0 von 0 Einträgen",
    "sInfoFiltered":    "(gefiltert von _MAX_ Einträgen)",
    "sInfoPostFix":     "",
    "sInfoThousands":   ".",
    "sLengthMenu":      "_MENU_ Einträge anzeigen",
    "sLoadingRecords":  "Wird geladen...",
    "sProcessing":      "Bitte warten...",
    "sSearch":          "Suchen",
    "sZeroRecords":     "Keine Einträge vorhanden.",
    "oPaginate": {
        "sFirst":       "Erste",
        "sPrevious":    "Zurück",
        "sNext":        "Nächste",
        "sLast":        "Letzte"
    },
    "oAria": {
        "sSortAscending":  ": aktivieren, um Spalte aufsteigend zu sortieren",
        "sSortDescending": ": aktivieren, um Spalte absteigend zu sortieren"
    }
}
});
</script>