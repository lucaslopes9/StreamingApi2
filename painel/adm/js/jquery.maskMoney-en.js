jQuery(function($){
	var ExecutarValor = function(){
			$('#EditarValorCobrado').maskMoney({
				prefix:"US$ ",
				decimal:".",
				thousands:","
			});
			$('#ValorCobrado').maskMoney({
				prefix:"US$ ",
				decimal:".",
				thousands:","
			});
			$('#EditarValorCobradoCab').maskMoney({
				prefix:"US$ ",
				decimal:".",
				thousands:","
			});
	}  
	
	ExecutarValor();
});