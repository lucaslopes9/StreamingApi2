<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('TesteAdicionar');
$VerificarAcesso = VerificarAcesso('teste', $ColunaAdmin);
$AdminAdicionar = $VerificarAcesso[0];
$CadUser = InfoUser(2);
 
if($AdminAdicionar == 'S'){
	
if ($_SERVER['REQUEST_METHOD'] == 'POST') {

echo "<div class=\"modal animated fadeIn\" id=\"EditarAdmin\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['Adicionar']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"AdicionarUser form-horizontal\" action=\"javascript:MDouglasMS();\">
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['ed']."</label>
                            	<div class=\"col-md-9\">                                        
   								<div style=\"border:0px; padding: 0px 0px 5px 0px;\" class=\"col-md-5\"><label class=\"check\"><input name=\"EnviarEmail\" id=\"EnviarEmail\" type=\"checkbox\" class=\"icheckbox\" /> ".$_TRA['email']."</label></div>
								<div style=\"border:0px; padding: 0px 0px 5px 0px;\" class=\"col-md-5\"><label class=\"check\"><input name=\"EnviarSMS\" id=\"EnviarSMS\" type=\"checkbox\" class=\"icheckbox\" /> ".$_TRA['sms']."</label></div>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">Enviar com</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EnviarCOM\" name=\"EnviarCOM\">";
									
									$CadUser = InfoUser(2);
									$bloqueado = "N";
									$SQLEnviarC1 = "SELECT id, email FROM email_adicionar WHERE bloqueado = :bloqueado AND CadUser = :CadUser";
									$SQLEnviarC1 = $painel_geral->prepare($SQLEnviarC1);
									$SQLEnviarC1->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
									$SQLEnviarC1->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
									$SQLEnviarC1->execute();
									$TotalEnviarC = count($SQLEnviarC1->fetchAll());
	
									if($TotalEnviarC > 0){
										$SQLEnviarC1->execute();
										$LnEnviarC = $SQLEnviarC1->fetch();
										echo "<option value=\"".$LnEnviarC['id']."\">".$LnEnviarC['email']."</option>";
									}
	
									$bloqueado = "S";
									$SQLEnviarC1 = "SELECT id, email FROM email_adicionar WHERE bloqueado = :bloqueado AND CadUser = :CadUser";
									$SQLEnviarC1 = $painel_geral->prepare($SQLEnviarC1);
									$SQLEnviarC1->bindParam(':bloqueado', $bloqueado, PDO::PARAM_STR);
									$SQLEnviarC1->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
									$SQLEnviarC1->execute();
									while($LnEnviarC = $SQLEnviarC1->fetch()){
										echo "<option value=\"".$LnEnviarC['id']."\">".$LnEnviarC['email']."</option>";
									}
									
									
									
                                    echo "</select>
                                 </div>
                        </div>
						
						 <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['vpe']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarPorEmail\" name=\"EditarPorEmail\">
									<option value=\"N\">".$_TRA['nao']."</option>
									<option value=\"S\">".$_TRA['sim']."</option>
                                    </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['vps']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarPorSMS\" name=\"EditarPorSMS\">
									<option value=\"N\">".$_TRA['nao']."</option>
									<option value=\"S\">".$_TRA['sim']."</option>
								</select>
                                 </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['nome']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarNome\" name=\"EditarNome\" type=\"text\" class=\"form-control\">
                            </div>
                        </div>
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['sobrenome']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarSobrenome\" name=\"EditarSobrenome\" type=\"text\" class=\"form-control\">
                            </div>
                        </div>
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Usuario']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" value=\"". rand(1,100000000)."\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarUsuario\" name=\"EditarUsuario\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Senha']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" value=\"". rand(1,100000000)."\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarUsuario\" name=\"EditarSenha\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['email']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarEmail\" name=\"EditarEmail\" type=\"text\" class=\"validate[custom[email]] form-control\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['celular']."</label>
                            <div class=\"col-md-9\">
                                <input onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarCelular\" name=\"EditarCelular\" type=\"text\" class=\"mask_phone_ext validate[custom[phone]] form-control\">
                            </div>
                        </div>
				
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['DataPremio']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" class=\"form-control select\" id=\"EditarPremium\" name=\"EditarPremium\">
									".VerificarTempoTeste()."
                                    </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['xml']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"XML\" name=\"XML\">
									<option value=\"S\">".$_TRA['sim']."</option>
									<option value=\"N\">".$_TRA['nao']."</option>
                                    </select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['obs']."</label>
                            <div class=\"col-md-9\">
							    <textarea pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" rows=\"10\" class=\"form-control\" id=\"obs\" name=\"obs\"></textarea>
                            </div>
                        </div>
													
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Perfil']."</label>
                            <div class=\"col-md-9\">
							".PerfilAdminEditar($CadUser, 0, 4)."
                            </div>
                        </div>
						
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarAdicionar btn btn-danger\">".$_TRA['Adicionar']."</button>
                        <button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>
<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
<script type='text/javascript' src='js/plugins/maskedinput/jquery.maskedinput.min.js'></script>

<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>

<!-- START TEMPLATE -->    
<?php include_once("js/settings".Idioma(2).".php"); ?>     
<script type="text/javascript" src="js/plugins.js"></script>  
<!-- END TEMPLATE -->      


<script>
$("#EditarAdmin").modal("show");

$(function(){  
 $("button.SalvarAdicionar").click(function() { 
 
 		var Data = $(".AdicionarUser").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarAdicionarTeste.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});
</script>

<?php  
}
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>