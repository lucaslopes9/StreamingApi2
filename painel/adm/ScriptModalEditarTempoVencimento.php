<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;
	
$ColunaAcesso = array('OpcoesVencimento');
$VerificarAcesso = VerificarAcesso('opcoes', $ColunaAcesso);
$OpcoesVencimento = $VerificarAcesso[0];
 
if($OpcoesVencimento == 'S'){
	
$id = (isset($_POST['id'])) ? $_POST['id'] : '';

$SQL = "SELECT tempo FROM tempovencimento WHERE id = :id";
$SQL = $painel_geral->prepare($SQL);
$SQL->bindParam(':id', $id, PDO::PARAM_INT);
$SQL->execute();
$Ln = $SQL->fetch();

$tempo = empty($Ln['tempo']) ? 0 : $Ln['tempo'];
$Stempo = $tempo > 1 ? $_TRA['dias'] : $_TRA['dia'];
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['editar']." (".$tempo." ".$Stempo.")</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"EditarTempoTeste form-horizontal\" action=\"javascript:MDouglasMS();\">
						
                       
                         <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['Tempo']."</label>
                            	<div class=\"col-md-9\">
                                	<input type=\"text\" name=\"EditarTempo\" id=\"EditarTempo\" class=\"form-control spinner_default\" value=\"".$tempo."\"/>
                                </div>
                        </div>
						
						<input type=\"hidden\" id=\"id\" name=\"id\" value=\"".$id."\">

						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"BotaoTempoTeste btn btn-danger\">".$_TRA['editar']."</button>
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
 $("button.BotaoTempoTeste").click(function() { 
 
		 var Data = $(".EditarTempoTeste").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarEditarTempoVencimento.php', Data, function(resposta) {
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