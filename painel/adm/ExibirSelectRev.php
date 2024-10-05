<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('RevAdicionar');
$VerificarAcesso = VerificarAcesso('rev', $ColunaAdmin);
$AdminAdicionar = $VerificarAcesso[0];
 
if($AdminAdicionar == 'S'){
	
$id = isset($_POST['id']) ? $_POST['id'] : '';

if($id == "S"){
	
echo "
	<div class=\"form-group\">
    		<label class=\"col-md-3 control-label\">".$_TRA['Cota']."</label>
        	<div class=\"col-md-9\">
           		<input id=\"EditarCota\" name=\"EditarCota\" type=\"text\" class=\"form-control\">
            </div>
    </div>
	
	<div class=\"form-group\">
    		<label class=\"col-md-3 control-label\">".$_TRA['Tempo']."</label>
        	<div class=\"col-md-9\">
           		<input id=\"EditarTempo\" name=\"EditarTempo\" type=\"text\" class=\"form-control\">
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
                	<input type=\"text\" id=\"dp-3\" name=\"EditarPremium\" class=\"form-control\" />
                    <span class=\"input-group-addon\"><span class=\"glyphicon glyphicon-calendar\"></span></span>
                </div>
            </div>
    </div>
	
	<div class=\"form-group\">
    	<label class=\"col-md-3 control-label\">".$_TRA['valorsat']."</label>
        	<div class=\"col-md-9\">
            	<input id=\"EditarValorCobrado\" name=\"EditarValorCobrado\" type=\"text\" class=\"form-control\">
            </div>
    </div>
						
	<div class=\"form-group\">
    	<label class=\"col-md-3 control-label\">".$_TRA['valorcab']."</label>
        	<div class=\"col-md-9\">
            	<input id=\"EditarValorCobradoCab\" name=\"EditarValorCobradoCab\" type=\"text\" class=\"form-control\">
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