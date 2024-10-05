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
    "sEmptyTable":     "No data available in table",
    "sInfo":           "Showing _START_ to _END_ of _TOTAL_ entries",
    "sInfoEmpty":      "Showing 0 to 0 of 0 entries",
    "sInfoFiltered":   "(filtered from _MAX_ total entries)",
    "sInfoPostFix":    "",
    "sInfoThousands":  ",",
    "sLengthMenu":     "Show _MENU_ entries",
    "sLoadingRecords": "Loading...",
    "sProcessing":     "Processing...",
    "sSearch":         "Search:",
    "sZeroRecords":    "No matching records found",
    "oPaginate": {
        "sFirst":    "First",
        "sLast":     "Last",
        "sNext":     "Next",
        "sPrevious": "Previous"
    },
    "oAria": {
        "sSortAscending":  ": activate to sort column ascending",
        "sSortDescending": ": activate to sort column descending"
    }
}
});
</script>