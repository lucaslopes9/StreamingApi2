jQuery(function($){
	var ExecutarValor = function(){
			$('#EditarValorCobrado').maskMoney({
				suffix:" €",
				decimal:".",
				thousands:" "
			});
			$('#ValorCobrado').maskMoney({
				suffix:" €",
				decimal:".",
				thousands:" "
			});
			$('#EditarValorCobradoCab').maskMoney({
				suffix:" €",
				decimal:".",
				thousands:" "
			});
	}  
	
	ExecutarValor();
});