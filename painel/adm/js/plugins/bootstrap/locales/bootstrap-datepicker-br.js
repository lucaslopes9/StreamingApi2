/**
 * Brazilian translation for bootstrap-datepicker
 * Cauan Cabral <cauan@radig.com.br>
 */   
;(function($){
	$.fn.datepicker.dates['br'] = {
		days: ["Domingo", "Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado"],
		daysShort: ["Dom", "Seg", "Ter", "Qua", "Qui", "Sex", "Sáb"],
		daysMin: ["Do", "Se", "Te", "Qu", "Qu", "Se", "Sa"],
		months: ["Janeiro", "Fevereiro", "Março", "Abril", "Maio", "Junho", "Julho", "Agosto", "Setembro", "Outubro", "Novembro", "Dezembro"],
		monthsShort: ["Jan", "Fev", "Mar", "Abr", "Mai", "Jun", "Jul", "Ago", "Set", "Out", "Nov", "Dez"],
		today: "Hoje",
		monthsTitle: "Meses",
		clear: "Limpar",
		format: "dd/mm/yyyy"
	};
}(jQuery));

$(function(){
	$('.input-group.date').datepicker({
   	 	format: 'dd/mm/yyyy',
    	language: 'br',
   		weekStart: 0,
    	startDate: false,
    	todayHighlight: true,
		autoclose: true
	});
});

$(function(){
	$('.EntreDatasPicker').datepicker({
   	 	format: 'dd/mm/yyyy',
    	language: 'br',
   		weekStart: 0,
    	startDate: false,
    	todayHighlight: true,
		autoclose: true
	});
});
