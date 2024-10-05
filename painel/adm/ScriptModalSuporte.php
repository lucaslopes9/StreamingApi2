<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$comprovante = (isset($_POST['comprovante'])) ? $_POST['comprovante'] : 'N';

$titulo = $comprovante == "S" ? $_TRA['ecompro'] : $_TRA['eSuporte'];
$assunto = $comprovante == "S" ? "value=\"".$_TRA['Comprovante']."\" disabled" : "";
		
echo "<div class=\"modal animated fadeIn\" id=\"EditarModal\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$titulo."</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"EnviarSuporte form-horizontal\" action=\"javascript:MDouglasMS();\" enctype=\"multipart/form-data\" method=\"post\">
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Assunto']."</label>
                            <div class=\"col-md-9\">
                                <input id=\"assunto\" name=\"assunto\" type=\"text\" class=\"validate[required] form-control\" ".$assunto.">
                            </div>
                        </div>";
                       
					   if($comprovante == "S"){
					  	 echo "<input type=\"hidden\" id=\"assunto\" name=\"assunto\" value=\"".$_TRA['Comprovante']."\" />";
					   }
						
						echo "<div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['Mensagem']."</label>
                            <div class=\"col-md-9\">
							    <textarea class=\"summernote\" id=\"mensagem\" name=\"mensagem\"></textarea>
                            </div>
                        </div>

						<input type=\"hidden\" id=\"Comprovante\" name=\"Comprovante\" value=\"".$comprovante."\" />
												
						</form>
                    </div>
                    <div class=\"modal-footer\">
						<div id=\"StatusModal\"></div>
						<button type=\"button\" class=\"btn btn-default\" data-dismiss=\"modal\">".$_TRA['fechar']."</button>
                        <button type=\"button\" class=\"ESuporte btn btn-success\">".$_TRA['Enviar']."</button>
                    </div>
                </div>
            </div>
        </div>";
?>

<script type='text/javascript' src='js/plugins/validationengine/languages/jquery.validationEngine<?php echo Idioma(2); ?>.js'></script>
<script type='text/javascript' src='js/plugins/validationengine/jquery.validationEngine.js'></script>
<script type="text/javascript" src="js/plugins/bootstrap/bootstrap-select.js"></script>

<script type="text/javascript" src="js/plugins/summernote/summernote<?php echo Idioma(2); ?>.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap-file-input.js"></script>
<script type='text/javascript' src='js/plugins.js'></script>

<script>
$("#EditarModal").modal("show");

$(function(){  
 $("button.ESuporte").click(function() { 
 								
						pageLoadingFrame("show");
						
						var formData = new FormData($(".EnviarSuporte")[0]); 
						formData.append( 'mensagem', $('.EnviarSuporte textarea[name="mensagem"]').code() );
						
  						$.ajax({
    						url: 'UploadAnexoSuporte.php',
     						type: 'POST',
     						data: formData,
     						async: false,
     						cache: false,
     						contentType: false,
     						enctype: 'multipart/form-data',
    						processData: false,
     						success: function (response) {
								setTimeout(function(){
                       				pageLoadingFrame("hide");
									$("#StatusGeral").append(response);
              					},1000);
     						}
   						});
						
				});
			});
</script>
   
<?php  
}else{
	echo Redirecionar('login.php');
}
?>