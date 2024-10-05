<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('AdminEditar');
$VerificarAcesso = VerificarAcesso('admin', $ColunaAdmin);
$AdminEditar = $VerificarAcesso[0];

if($AdminEditar == 'S'){
	
if ($_SERVER['REQUEST_METHOD'] == 'POST') {

$usuario = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';
$UsuarioOnline = InfoUser(2);

if(!empty($usuario)){

$SQLUser = "SELECT nome, sobrenome, usuario, senha, email, celular, ValorCobrado, ValorCobradoCabo, obs FROM admin WHERE usuario = :usuario";
$SQLUser = $painel_user->prepare($SQLUser);
$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
$SQLUser->execute();
$LnUser = $SQLUser->fetch();

echo "<div class=\"modal animated fadeIn\" id=\"EditarAdmin\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['editar']." ".$usuario."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"EditarAdministrador form-horizontal\" action=\"javascript:MDouglasMS();\">
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['nome']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarNome\" name=\"EditarNome\" type=\"text\" class=\"validate[required] form-control\" value=\"".$LnUser['nome']."\">
                            </div>
                        </div>
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['sobrenome']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarSobrenome\" name=\"EditarSobrenome\" type=\"text\" class=\"validate[required] form-control\" value=\"".$LnUser['sobrenome']."\">
                            </div>
                        </div>";
						
						if($LnUser['usuario'] != $UsuarioOnline){
                        echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Senha']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarUsuario\" name=\"EditarSenha\" type=\"text\" class=\"validate[required] form-control\" value=\"".$LnUser['senha']."\">
                            </div>
                        </div>";
						}

						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['email']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarEmail\" name=\"EditarEmail\" type=\"text\" class=\"validate[required,custom[email]] form-control\" value=\"".$LnUser['email']."\">
                            </div>
                        </div>
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['celular']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarCelular\" name=\"EditarCelular\" type=\"text\" class=\"mask_phone_ext validate[required,custom[phone]] form-control\" value=\"".$LnUser['celular']."\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['valorsat']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarValorCobrado\" name=\"EditarValorCobrado\" type=\"text\" class=\"form-control\" value=\"".str_replace(".",",",$LnUser['ValorCobrado'])."\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['valorcab']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarValorCobradoCab\" name=\"EditarValorCobradoCab\" type=\"text\" class=\"form-control\" value=\"".str_replace(".",",",$LnUser['ValorCobradoCabo'])."\">
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['obs']."</label>
                            <div class=\"col-md-9\">
							    <textarea rows=\"10\" class=\"form-control\" id=\"obs\" name=\"obs\">".$LnUser['obs']."</textarea>
                            </div>
                        </div>
						
						<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Perfil']."</label>
                            <div class=\"col-md-9\">
							".PerfilAdminEditar($UsuarioOnline, $usuario, 1)."
                            </div>
                        </div>

						<input type=\"hidden\" name=\"EditarUsuario\" id=\"EditarUsuario\" value=\"".$LnUser['usuario']."\">
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
 
 		var Data = $(".EditarAdministrador").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarEditarAdmin.php', Data, function(resposta) {
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
}
}
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>