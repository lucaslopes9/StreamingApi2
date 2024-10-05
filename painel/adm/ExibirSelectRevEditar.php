<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('RevEditar');
$VerificarAcesso = VerificarAcesso('rev', $ColunaAdmin);
$AdminAdicionar = $VerificarAcesso[0];
 
if($AdminAdicionar == 'S'){
	
$id = isset($_POST['id']) ? $_POST['id'] : '';
$usuario = isset($_POST['usuario']) ? $_POST['usuario'] : '';

$SQLUser = "SELECT data_premio, ValorCobrado, ValorCobradoCabo, Cota, CotaDias FROM rev WHERE usuario = :usuario";
$SQLUser = $painel_user->prepare($SQLUser);
$SQLUser->bindParam(':usuario', $usuario, PDO::PARAM_STR);
$SQLUser->execute();
$LnUser = $SQLUser->fetch();

$data_premio = empty($LnUser['data_premio']) ? "" : $LnUser['data_premio'];
$ValorCobrado = empty($LnUser['ValorCobrado']) ? "" : trim($LnUser['ValorCobrado']);
$ValorCobradoCabo = empty($LnUser['ValorCobradoCabo']) ? "" : trim($LnUser['ValorCobradoCabo']);
$Cota = empty($LnUser['Cota']) ? 0 : trim($LnUser['Cota']);
$CotaDias = empty($LnUser['CotaDias']) ? 0 : trim($LnUser['CotaDias']);

if($id == "S"){
	
echo "
	<div class=\"form-group\">
    		<label class=\"col-md-3 control-label\">".$_TRA['Cota']."</label>
        	<div class=\"col-md-9\">
           		<input id=\"EditarCota\" name=\"EditarCota\" type=\"text\" class=\"form-control\" value=\"".$Cota."\">
            </div>
    </div>
	
	<div class=\"form-group\">
    		<label class=\"col-md-3 control-label\">".$_TRA['Tempo']."</label>
        	<div class=\"col-md-9\">
           		<input id=\"EditarTempo\" name=\"EditarTempo\" type=\"text\" class=\"form-control\" value=\"".$CotaDias."\">
            </div>
    </div>
";

}
else{
	echo "
	<div class=\"form-group\">
    	<label class=\"col-md-3 control-label\">".$_TRA['DataPremio']."</label>
        	<div class=\"col-md-9\">
				<div class=\"input-group date\">
                	<input type=\"text\" id=\"dp-3\" name=\"EditarPremium\" class=\"form-control\" value=\"".ConverterDataTime($data_premio)."\"/>
                    <span class=\"input-group-addon\"><span class=\"glyphicon glyphicon-calendar\"></span></span>
                </div>
            </div>
    </div>
	
	
	<div class=\"form-group\">
    	<label class=\"col-md-3 control-label\">".$_TRA['valorsat']."</label>
        	<div class=\"col-md-9\">
            	<input id=\"EditarValorCobrado\" name=\"EditarValorCobrado\" type=\"text\" class=\"form-control\" value=\"".str_replace(".",",",$ValorCobrado)."\">
            </div>
    </div>
						
	<div class=\"form-group\">
    	<label class=\"col-md-3 control-label\">".$_TRA['valorcab']."</label>
        	<div class=\"col-md-9\">
            	<input id=\"EditarValorCobradoCab\" name=\"EditarValorCobradoCab\" type=\"text\" class=\"form-control\" value=\"".str_replace(".",",",$ValorCobradoCabo)."\">
           </div>
    </div>
	";
}
?>

<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-datepicker.js"></script>
<script type="text/javascript" src="js/plugins/bootstrap/locales/bootstrap-datepicker<?php echo Idioma(2); ?>.js"></script>

<script type="text/javascript" src="js/jquery.maskMoney.js"></script>
<script type="text/javascript" src="js/jquery.maskMoney<?php echo Idioma(2); ?>.js"></script>

<?php
}else{
	echo Redirecionar('index.php');
}
}else{
	echo Redirecionar('login.php');
}	
?>