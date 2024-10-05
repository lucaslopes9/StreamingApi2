<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
if(ProtegePag() == true){
global $_TRA;

$ColunaAdmin = array('RevLogin');
$VerificarAcesso = VerificarAcesso('rev', $ColunaAdmin);
$RevLogin = $VerificarAcesso[0];

if($RevLogin == 'S'){
	
if ($_SERVER['REQUEST_METHOD'] == 'POST') {

$usuario = (isset($_POST['usuario'])) ? $_POST['usuario'] : '';

if(!empty($usuario)){

echo "<div class=\"modal animated fadeIn\" id=\"EditarAdmin\" tabindex=\"-1\" role=\"dialog\" aria-labelledby=\"smallModalHead\" aria-hidden=\"true\">
            <div class=\"modal-dialog\">
                <div class=\"modal-content\">
                    <div class=\"modal-header\">
                        <button type=\"button\" class=\"close\" data-dismiss=\"modal\"><span aria-hidden=\"true\">&times;</span><span class=\"sr-only\">".$_TRA['fechar']."</span></button>
                        <h4 class=\"modal-title\" id=\"smallModalHead\">".$_TRA['au']." (".$usuario.")</h4>
                    </div>
                    <div class=\"modal-body form-horizontal form-group-separated\">     
						<form id=\"validate\" role=\"form\" class=\"EditarAdministrador form-horizontal\" action=\"javascript:MDouglasMS();\">
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['ua']."</label>
                            <div class=\"col-md-9\">
                                <input type=\"text\" class=\"validate[required] form-control\" value=\"".$usuario."\" disabled=\"disabled\">
								<input id=\"UserAtual\" name=\"UserAtual\" type=\"hidden\" value=\"".$usuario."\">
                            </div>
                        </div>
						
                        <div class=\"form-group\">
                            <label class=\"col-md-3 control-label\">".$_TRA['nu']."</label>
                            <div class=\"col-md-9\">
                                <input pattern=\"[A-Za-z]\" onkeypress=\"sem_acento(event)\" onkeydown =\"onKeyDown()\" id=\"UserNovo\" name=\"UserNovo\" type=\"text\" class=\"validate[required] form-control\">
                            </div>
                        </div>
						
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

<script>
$("#EditarAdmin").modal("show");

$(function(){  
 $("button.SalvarEditar").click(function() { 
 
 		var Data = $(".EditarAdministrador").serialize();
		
		$('#StatusModal').html("<center><img src=\"img/owl/AjaxLoader.gif\"><br><br></center>");
		
		$.post('EnviarAlterarLoginRev.php', Data, function(resposta) {
				$("#StatusModal").html('');
				$("#StatusGeral").append(resposta);
		});
	});
});
</script>
   
   <script language="javascript">
function onKeyDown() {
  // current pressed key
  var pressedKey = String.fromCharCode(event.keyCode).toLowerCase();
  if (event.ctrlKey && (pressedKey == "c" || 
                        pressedKey == "x" ||
                        pressedKey == "v")) {
    // disable key press porcessing
    event.returnValue = false;
  }
} // onKeyDown
</script>


<script language=JavaScript>
<!--
function desabilitar(){
    alert ("Função desabilitada.\n\nDesculpe o incômodo.")
    return false
}
document.oncontextmenu=desabilitar
// -->
</script> 

<script language="javascript">
function sem_acento(e,args)
{		
  var evt = (document.all)? event.keyCode : e.charCode;
  var valid_chars = '0123456789abcdefghijlmnopqrstuvxzwykABCDEFGHIJLMNOPQRSTUVXZWYK@.-_ '+args;	
  var chr= String.fromCharCode(evt);	// pegando a tecla digitada
  if (valid_chars.indexOf(chr)<0){
    e.preventDefault();
    alert('caracter invalido');
  }
}
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