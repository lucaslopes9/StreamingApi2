<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('RevEditar');
$VerificarAcesso = VerificarAcesso('rev', $ColunaAdmin);
$AdminEditar = $VerificarAcesso[0];

if($AdminEditar == 'S'){
	
if ($_SERVER['REQUEST_METHOD'] == 'POST') {

$usuario = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';
$UsuarioOnline = InfoUser(2);
$VerificarInfoPre = VerificarInfoPre();

if(!empty($usuario)){

$SQLUser = "SELECT nome, sobrenome, senha, email, celular, VencEmail, VencSMS, PrePago, data_premio, ValorCobrado, ValorCobradoCabo, Cota, CotaDias, obs, LimiteTeste, LimiteUser FROM rev WHERE usuario = :usuario";
$SQLUser = $painel_user->prepare($SQLUser);
$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
$SQLUser->execute();
$LnUser = $SQLUser->fetch();

$VencEmail = empty($LnUser['VencEmail']) ? "S" : $LnUser['VencEmail'];
$VencSMS = empty($LnUser['VencSMS']) ? "S" : $LnUser['VencSMS'];
$nome = empty($LnUser['nome']) ? "" : $LnUser['nome'];
$sobrenome = empty($LnUser['sobrenome']) ? "" : $LnUser['sobrenome'];
$senha = empty($LnUser['senha']) ? "" : $LnUser['senha'];
$email = empty($LnUser['email']) ? "" : $LnUser['email'];
$celular = empty($LnUser['celular']) ? "" : $LnUser['celular'];
$PrePago = empty($LnUser['PrePago']) ? "N" : $LnUser['PrePago'];
$data_premio = empty($LnUser['data_premio']) ? "" : $LnUser['data_premio'];
$ValorCobrado = empty($LnUser['ValorCobrado']) ? "" : str_replace(".",",",trim($LnUser['ValorCobrado']));
$ValorCobradoCabo = empty($LnUser['ValorCobradoCabo']) ? "" : str_replace(".",",",trim($LnUser['ValorCobradoCabo']));
$Cota = empty($LnUser['Cota']) ? 0 : trim($LnUser['Cota']);
$CotaDias = empty($LnUser['CotaDias']) ? 0 : trim($LnUser['CotaDias']);
$obs = empty($LnUser['obs']) ? "" : trim($LnUser['obs']);
$LimiteTeste = empty($LnUser['LimiteTeste']) ? 0 : trim($LnUser['LimiteTeste']);
$LimiteUser = empty($LnUser['LimiteUser']) ? 0 : trim($LnUser['LimiteUser']);

echo "<div class=\"modal animated fadeIn\" id=\"EditarAdmin\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['editar']." ".$usuario."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"EditarRevendedor form-horizontal\" action=\"javascript:MDouglasMS();\">
						
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
                                	<select class=\"form-control select\" id=\"EditarPorEmail\" name=\"EditarPorEmail\">";
									
									if($VencEmail == "S"){
									echo "<option value=\"S\">".$_TRA['sim']."</option>
									<option value=\"N\">".$_TRA['nao']."</option>";
									}
									else{
									echo "<option value=\"N\">".$_TRA['nao']."</option>
									<option value=\"S\">".$_TRA['sim']."</option>";	
									}
                                   
								    echo "</select>
                                 </div>
                        </div>
						
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['vps']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarPorSMS\" name=\"EditarPorSMS\">";
									
									if($VencSMS == "S"){
									echo "<option value=\"S\">".$_TRA['sim']."</option>
									<option value=\"N\">".$_TRA['nao']."</option>";
									}
									else{
									echo "<option value=\"N\">".$_TRA['nao']."</option>
									<option value=\"S\">".$_TRA['sim']."</option>";	
									}
									
                                    echo "</select>
                                 </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['nome']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarNome\" name=\"EditarNome\" type=\"text\" class=\"form-control\" value=\"".$nome."\">
                            </div>
                        </div>
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['sobrenome']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarSobrenome\" name=\"EditarSobrenome\" type=\"text\" class=\"form-control\" value=\"".$sobrenome."\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Senha']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarUsuario\" name=\"EditarSenha\" type=\"text\" class=\"validate[required] form-control\" value=\"".$senha."\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['email']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarEmail\" name=\"EditarEmail\" type=\"text\" class=\"validate[custom[email]] form-control\" value=\"".$email."\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['celular']."</label>
                            <div class=\"col-md-9\">
                                <input onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarCelular\" name=\"EditarCelular\" type=\"text\" class=\"mask_phone_ext validate[custom[phone]] form-control\" value=\"".$celular."\">
                            </div>
                        </div>
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['ldt']."</label>
                            	<div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" type=\"text\" name=\"EditarLimiteTeste\" id=\"EditarLimiteTeste\" class=\"form-control spinner_default\" value=\"".$LimiteTeste."\"/>
                                </div>
                        </div>
						<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">Limite de Usuário</label>
                            	<div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" type=\"text\" name=\"EditarLimiteUser\" id=\"EditarLimiteUser\" class=\"form-control spinner_default\" value=\"".$LimiteUser."\"/>
                                </div>
                        </div>
						";
						
						if($VerificarInfoPre[0] == "N"){
						echo "<div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['prepago']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"EditarPrePago\" name=\"EditarPrePago\">";
									
									if($PrePago == "S"){
									echo "<option value=\"S\">".$_TRA['sim']."</option>
									<option value=\"N\">".$_TRA['nao']."</option>";
									}
									else{
									echo "<option value=\"N\">".$_TRA['nao']."</option>
									<option value=\"S\">".$_TRA['sim']."</option>";	
									}
									
                                    echo "</select>
                                 </div>
                        </div>";
						}
						
						if($VerificarInfoPre[0] == "N"){
						
						echo "<div class=\"form-group\" id=\"StatusPre\">";
						
						if($PrePago == "S"){
							
						echo "
						<div class=\"form-group\">
    						<label class=\"col-md-3 control-label\">".$_TRA['Cota']."</label>
        						<div class=\"col-md-9\">
           							<input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarCota\" name=\"EditarCota\" type=\"text\" class=\"form-control\" value=\"".$Cota."\">
            					</div>
    					</div>
	
						<div class=\"form-group\">
    						<label class=\"col-md-3 control-label\">".$_TRA['Tempo']."</label>
        						<div class=\"col-md-9\">
           							<input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarTempo\" name=\"EditarTempo\" type=\"text\" class=\"form-control\" value=\"".$CotaDias."\">
           						</div>
    					</div>
";
							
						}else{
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['DataPremio']."</label>
                            <div class=\"col-md-9\">
								<div class=\"input-group date\">
                                	<input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" type=\"text\" id=\"dp-3\" name=\"EditarPremium\" class=\"form-control\" value=\"".ConverterDataTime($data_premio)."\"/>
                                    <span class=\"input-group-addon\"><span class=\"glyphicon glyphicon-calendar\"></span></span>
                            	</div>
                            </div>
						</div>
							
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['valorsat']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarValorCobrado\" name=\"EditarValorCobrado\" type=\"text\" class=\"form-control\" value=\"".$ValorCobrado."\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['valorcab']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarValorCobradoCab\" name=\"EditarValorCobradoCab\" type=\"text\" class=\"form-control\" value=\"".$ValorCobradoCabo."\">
                            </div>
                        </div>";
						}
							
						echo "</div>";
						
						}
						else{
						
						echo "
						<div class=\"form-group\">
    						<label class=\"col-md-3 control-label\">".$_TRA['Cota']."</label>
        						<div class=\"col-md-9\">
           							<input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarCota\" name=\"EditarCota\" type=\"text\" class=\"form-control\" value=\"".$Cota."\">
            					</div>
    					</div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['valorsat']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarValorCobrado\" name=\"EditarValorCobrado\" type=\"text\" class=\"form-control\" value=\"".$ValorCobrado."\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['valorcab']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"EditarValorCobradoCab\" name=\"EditarValorCobradoCab\" type=\"text\" class=\"form-control\" value=\"".$ValorCobradoCabo."\">
                            </div>
                        </div>";
							
						}
						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['obs']."</label>
                            <div class=\"col-md-9\">
							    <textarea pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" rows=\"10\" class=\"form-control\" id=\"obs\" name=\"obs\">".$obs."</textarea>
                            </div>
                        </div>";
						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Perfil']."</label>
                            <div class=\"col-md-9\">
							".PerfilAdminEditar($UsuarioOnline, $usuario, 2)."
                            </div>
                        </div>
						
						
						<input type=\"hidden\" name=\"EditarUsuario\" id=\"EditarUsuario\" value=\"".$usuario."\">
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarEditar btn btn-danger\">".$_TRA['alterar']."</button>
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

<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-datepicker.js"></script>
<script type="text/javascript" src="js/plugins/bootstrap/locales/bootstrap-datepicker<?php echo Idioma(2); ?>.js"></script>

<!-- START TEMPLATE -->      
<?php include_once("js/settings".Idioma(2).".php"); ?> 
<script type="text/javascript" src="js/plugins.js"></script>    
<!-- END TEMPLATE -->  



<script type="text/javascript" src="js/jquery.maskMoney.js"></script>
<script type="text/javascript" src="js/jquery.maskMoney<?php echo Idioma(2); ?>.js"></script>    
<script>
$("#EditarAdmin").modal("show");

$(function(){  
 $("button.SalvarEditar").click(function() { 
 
 		var Data = $(".EditarRevendedor").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarEditarRev.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});

$(function(){
	$(".EditarRevendedor select[name=EditarPrePago]").change(function(){
		
		var id = $(this).val();
		var usuario = '<?php echo $usuario; ?>';
		
		$.post('ExibirSelectRevEditar.php', {id: id, usuario: usuario}, function(resposta) {
				$("#StatusPre").html('');
				$("#StatusPre").html(resposta);
		});
	});
});

$(function(){
        //Spinner
        $(".spinner_default").spinner({
			min: 0,
			step: 1, 
			numberFormat: "n"
		});                
        //End spinner
});
</script>
   
<?php  
}
}
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>