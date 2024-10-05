<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAcesso = array('SMSModeloAdicionar');
$VerificarAcesso = VerificarAcesso('sms_modelo', $ColunaAcesso);
$SMSModeloAdicionar = $VerificarAcesso[0];
 
if($SMSModeloAdicionar == 'S'){
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['Adicionar']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AdicionarModelo form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Tipo']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"tipo\" name=\"tipo\">
										<option value=\"Painel\">".$_TRA['Preferencia']."</option>
										<option value=\"SMS\">".$_TRA['sms']."</option>
                                     </select>
                                 </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Assunto']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"assunto\" name=\"assunto\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
                       
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Mensagem']."</label>
                            <div class=\"col-md-9\">
							    <textarea class=\"form-control\" id=\"mensagem\" name=\"mensagem\" rows=\"6\">[MEUEMAIL]: ".$_TRA['MEUEMAIL']."\n[MEUNOME]: ".$_TRA['MEUNOME']."\n[LGCLIENTE]: ".$_TRA['LGCLIENTE']."\n[SNCLIENTE]: ".$_TRA['SNCLIENTE']."\n[NMCLIENTE]: ".$_TRA['NMCLIENTE']."\n[VCCLIENTE]: ".$_TRA['VCCLIENTE']."\n[NOMEPERFIL]: ".$_TRA['NOMEPERFIL']."\n[URLPERFIL]: ".$_TRA['URLPERFIL']."\n[PORTAPERFIL]: ".$_TRA['PORTAPERFIL']."\n[DESKEYS]: ".$_TRA['Deskeys']."\n[URLPAINEL]: ".$_TRA['URLPAINEL']."\n[NOMEPAINEL]: ".$_TRA['NOMEPAINEL']."</textarea>
                            </div>
                        </div>
						
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarModelo btn btn-danger\">".$_TRA['Adicionar']."</button>
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>

<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>

<script type='text/javascript' src='js/plugins.js'></script>

<script>
$("#EditarModal").modal("show");

$(function(){  
 $("button.SalvarModelo").click(function() { 
  		
		var Data = $(".AdicionarModelo").serialize();
		 		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarAdicionarSMSModelo.php', Data, function(resposta) {
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