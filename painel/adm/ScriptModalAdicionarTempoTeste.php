<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAcesso = array('TesteTempoAdicionar');
$VerificarAcesso = VerificarAcesso('tempoteste', $ColunaAcesso);
$SMSadicionarAdicionar = $VerificarAcesso[0];
 
if($SMSadicionarAdicionar == 'S'){
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['Adicionar']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AdicionarTempoTeste form-horizontal\" action=\"javascript:MDouglasMS();\">
						
                        
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Tempo']."</label>
                            	<div class=\"col-md-9\">
                                	<input type=\"text\" name=\"EditarTempo\" id=\"EditarTempo\" class=\"form-control spinner_default\" value=\"1\"/>
                                </div>
                        </div>
						
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
						<button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                        <button type=\"button\" class=\"SalvarSMS btn btn-danger\">".$_TRA['Adicionar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>

<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
<script type='text/javascript' src='js/plugins.js'></script>

<script>
$("#EditarModal").modal("show");

$(function(){  
 $("button.SalvarSMS").click(function() { 
 
		 var Data = $(".AdicionarTempoTeste").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarAdicionarTempoTeste.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});

$(function(){
        //Spinner
        $(".spinner_default").spinner({
			min: 1,
			step: 1, 
			numberFormat: "n"
		});                
        //End spinner
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