<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAcesso = array('ServidorcspConfig');
$VerificarAcesso = VerificarAcesso('servidorcsp', $ColunaAcesso);
$ServidorcspConfig = $VerificarAcesso[0];
 
if($ServidorcspConfig == 'S'){
	
$SQL = "SELECT senha, deskeys, ip, iplock FROM painel_config";
$SQL = $painel_geral->prepare($SQL);
$SQL->execute();
$Ln = $SQL->fetch();

$deskeys = empty($Ln['deskeys']) ? "0102030405060708091011121314" : $Ln['deskeys'];
	
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['config']."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"ConfigPainel form-horizontal\" action=\"javascript:MDouglasMS();\">
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['SXML']."</label>
                            <div class=\"col-md-9\">
                            <input id=\"EditarSenha\" name=\"EditarSenha\" type=\"text\" class=\"validate[required] form-control\" value=\"".$Ln['senha']."\">
                            </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Deskeys']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"EditarDeskeys\" name=\"EditarDeskeys\" type=\"text\" class=\"validate[required,custom[integer],custom[number]] form-control\" value=\"".$deskeys."\">
                            </div>
                        </div>
					
					  <div class=\"form-group\">
                        	<label class=\"col-md-3 control-label\">".$_TRA['bpi']."</label>
                            	<div class=\"col-md-9\">                                        
                                	<select class=\"form-control select\" id=\"iplock\" name=\"iplock\">";
									
									if($Ln['iplock'] == "S"){
										echo "<option value=\"S\">".$_TRA['sim']."</option><option value=\"N\">".$_TRA['nao']."</option>";
									}
									else{
										echo "<option value=\"N\">".$_TRA['nao']."</option><option value=\"S\">".$_TRA['sim']."</option>";
									}
									
                                   echo " </select>
                                 </div>
                        </div>
               		
					 <div class=\"form-group\" id=\"StatusLockIp\">";
					 
					 	if($Ln['iplock'] == "S"){
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['IPper']."</label>
                            <div class=\"col-md-9\">
							<textarea rows=\"5\" class=\"validate[required] form-control\" id=\"EditarIP\" name=\"EditarIP\">".$Ln['ip']."</textarea>
                            </div>
                        </div>";
						}
						
					 echo "</div>
			   
						
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
                        <button type=\"button\" class=\"SalvarEditar btn btn-danger\">".$_TRA['salvar']."</button>
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
 $("button.SalvarEditar").click(function() { 
 
 		var Data = $(".ConfigPainel").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
				
		$.post('EnviarEditarConfig.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});

$(function(){
	$(".ConfigPainel select[name=iplock]").change(function(){
		
		var id = $(this).val();
		
		$.post('ExibirSelectConfigCSP.php', {id: id}, function(resposta) {
				$("#StatusLockIp").html('');
				$("#StatusLockIp").html(resposta);
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