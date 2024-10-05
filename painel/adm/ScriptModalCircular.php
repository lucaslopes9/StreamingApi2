<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
if(!empty($_SESSION['MensagemInterna'])){
				
echo "<div class=\"modal animated fadeIn\" id=\"EditarModalCircularExibir\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['atencao']."</h4>
                    </div>
					
                    <div class=\"modal-body form-horizontal StatusModalCircular\">".$_SESSION['MensagemInterna']."</div>
					
                    <div class=\"modal-footer\">
                        <button type=\"button\" class=\"BotaoEnviarCircularExibir btn btn-success\">".$_TRA['Ciente']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>

<script>
$("#EditarModalCircularExibir").modal("show");

$(function(){  
 $("button.BotaoEnviarCircularExibir").click(function() { 
		
		panel_refresh($(".StatusModalCircular"));
		
		$.post('EnviarMensagemCircularCiente.php', function(resposta) {
			
				setTimeout(panel_refresh($(".StatusModalCircular")),500);
			
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});
</script>
   
<?php  
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}
?>