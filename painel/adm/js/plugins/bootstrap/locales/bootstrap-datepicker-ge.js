/**
 * German translation for bootstrap-datepicker
 * Sam Zurcher <sam@orelias.ch>
 */
;(function($){
	$.fn.datepicker.dates['ge'] = {
		days: ["Sonntag", "Montag", "Dienstag", "Mittwoch", "Donnerstag", "Freitag", "Samstag"],
		daysShort: ["Son", "Mon", "Die", "Mit", "Don", "Fre", "Sam"],
		daysMin: ["So", "Mo", "Di", "Mi", "Do", "Fr", "Sa"],
		months: ["Januar", "Februar", "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober", "November", "Dezember"],
		monthsShort: ["Jan", "Feb", "Mär", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Okt", "Nov", "Dez"],
		today: "Heute",
		monthsTitle: "Monate",
		clear: "Löschen",
		weekStart: 1,
		format: "dd.mm.yyyy"
	};
}(jQuery));

$(function(){
	$('.input-group.date').datepicker({
   	 	format: 'yyyy/mm/dd',
    	language: 'ge',
   		weekStart: 0,
    	startDate: false,
    	todayHighlight: true,
		autoclose: true
	});
});

$(function(){
	$('.EntreDatasPicker').datepicker({
   	 	format: 'yyyy/mm/dd',
    	language: 'ge',
   		weekStart: 0,
    	startDate: false,
    	todayHighlight: true,
		autoclose: true
	});
});
