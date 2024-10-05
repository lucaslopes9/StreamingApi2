<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
$idioma = empty($_COOKIE['idioma']) ? "br" : $_COOKIE['idioma'];
$lang = empty($_GET['lang']) ? "" : $_GET['lang'];
if(!empty($lang)) SalvarIdioma($lang);
global $_TRA;
$VerificarInfoSite = VerificarInfoSite();

//Remove os cookies
unset($_SESSION['id'], $_SESSION['usuario'], $_SESSION['acesso']);

$GET = empty($_GET['r']) ? "" : $_GET['r'];
$CadUser = UrlTeste(2, $GET);

//Verificar se o revendedor tem acessos para criar testes
$grupo = "N";
$SQLUrlT = "SELECT RevUrldeTeste FROM rev WHERE CadUser = :CadUser AND grupo = :grupo";
$SQLUrlT = $painel_acessos->prepare($SQLUrlT);
$SQLUrlT->bindParam(':CadUser', $CadUser, PDO::PARAM_STR);
$SQLUrlT->bindParam(':grupo', $grupo, PDO::PARAM_STR);
$SQLUrlT->execute();
$LnUrlT = $SQLUrlT->fetch();
$RevUrldeTeste = $LnUrlT['RevUrldeTeste'];

$VerTeste = VerTeste($CadUser);
$TempoDias = $VerTeste[1] > 1 ? $_TRA['dias'] : $_TRA['dia'];

if( ($VerTeste[0] == 1) && ($RevUrldeTeste == "S") ){
	

$SQL = "SELECT status FROM captcha";
$SQL = $painel_geral->prepare($SQL);
$SQL->execute();
$Ln = $SQL->fetch();
$StatusCaptcha = $Ln['status'];
?>

<!DOCTYPE html>
<html lang="<?php echo $idioma; ?>" class="body-full-height">
    <head>        
        <!-- META SECTION -->
        <title><?php echo $VerificarInfoSite[0]; ?></title>            
        <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        
        <link rel="icon" href="favicon.ico" type="image/x-icon" />
        <!-- END META SECTION -->
        
        <!-- CSS INCLUDE -->        
        <link rel="stylesheet" type="text/css" id="theme" href="css/<?php echo $VerificarInfoSite[2]; ?>.css"/>
        <!-- EOF CSS INCLUDE -->                               
    </head>
    <body>
        
        <div class="registration-container">            
            <div class="registration-box animated fadeInDown">
                <div class="registration-logo"><?php echo $VerificarInfoSite[0]; ?></div>
				<div class="registration-legenda"><?php echo $VerificarInfoSite[1]; ?></div>
                <div class="registration-body">
                    <div class="registration-title"><strong><?php echo $_TRA['ct']; ?></strong>, <?php echo $VerTeste[1]." ".$TempoDias; ?></div>
                                        
                    <form action="javascript:MDouglasMS();" class="TesteCadastrar form-horizontal" method="post" id="FormLogin">
                    
                    <h4>Opção</h4>
                    <div class="form-group">
                    	<div class="col-md-12">                                        
                    		<select class="form-control select" id="OpcaoForm" name="OpcaoForm">
								<option value="T">Criar Teste</option>
								<option value="D">Descontar Cupom</option>
                    		</select>
                    	</div>
                    </div>
                    
                    <h4><?php echo $_TRA['dp']; ?></h4>
                    <div class="form-group">
                        <div class="col-md-12">
                            <input pattern="[A-Za-z]" onkeypress="sem_acento(event)" onkeydown ="onKeyDown()" name="nome" id="nome" type="text" class="form-control" placeholder="<?php echo $_TRA['nome']; ?>"/>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <div class="col-md-12">
                            <input pattern="[A-Za-z]" onkeypress="sem_acento(event)" onkeydown ="onKeyDown()" name="email" id="email" type="text" class="form-control" placeholder="<?php echo $_TRA['email']; ?>"/>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <div class="col-md-12">
                            <input onkeypress="sem_acento(event)" id="EditarCelular" name="EditarCelular" type="text" class="form-control" placeholder="WhatsApp"/>
                        </div>
                    </div>
                    
                    <span id="StatusOpcao">
                    	<h4><?php echo $_TRA['Operadora']; ?></h4>
                    	<div class="form-group">
                    		<div class="col-md-12">                                        
                        		<select class="form-control select" id="Operadora" name="Operadora">
								<?php echo SelectOperadora($CadUser); ?>
                            	</select>
                         	</div>
                    	</div>
                    </span>
                    
                    <?php
					if($StatusCaptcha == "S"){
					?>
                    <div class="form-group">
                   		<center>
                   	 		<div id="StatusCaptcha">
           						<?php include "CaptchaImg.php"; ?>
           					</div>
                        </center>
                    </div>
                    
                    <div class="form-group pointer" onClick="NovoCaptcha()">
                   	 	<div class="col-md-12 text-right">
                    		Novo Captcha
                    	</div>
                    </div>
                    
                    <div class="form-group">
                        <div class="col-md-12">
                            <input type="text" name="captcha" id="captcha" class="form-control" placeholder="Digite o Captcha"/>
                        </div>
                    </div>
                    <?php
					}
					?>
                                         
                    <div class="form-group push-up-30">
                        <div class="col-md-12">
                        	<div id="StatusCadastro"></div>
                            <input name="r" id="r" type="hidden" value="<?php echo $GET; ?>"/>
                            <button onClick="CriarTesteAutomatico()" class="CadastrarTeste btn btn-danger btn-block"><?php echo $_TRA['ct']; ?></button>
                        </div>
                    </div>
                    </form>
                </div>
                <div class="registration-footer">
                    <div class="pull-left">
                        &copy; 2020 <?php echo $VerificarInfoSite[0]; ?>
                    </div>
                    <div class="pull-right">
                       
                    </div>
                </div>
            </div>
            
        </div>
        
        <div id="StatusGeral"></div>  
        
 		 <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script src="js/jquery.maskedinput.js"></script>
        
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>
        <!-- END PLUGINS -->
  		
        <script type='text/javascript' src='js/plugins/bootstrap/bootstrap-select.js'></script>        

        
        <script type="text/javascript" src="js/plugins.js"></script>
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->
              
    </body>
</html>

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
  var valid_chars = '0123456789abcdefghijlmnopqrstuvxzwykABCDEFGHIJLMNOPQRSTUVXZWYK@-_. '+args;	
  var chr= String.fromCharCode(evt);	// pegando a tecla digitada
  if (valid_chars.indexOf(chr)<0){
    e.preventDefault();
    alert('caracter invalido');
  }
}
</script>

<script type="text/javascript">
jQuery("input#EditarCelular")
        .mask("(99) 9999-9999?9")
        .focusout(function (event) {  
            var target, phone, element;  
            target = (event.currentTarget) ? event.currentTarget : event.srcElement;  
            phone = target.value.replace(/\D/g, '');
            element = $(target);  
            element.unmask();  
            if(phone.length > 10) {  
                element.mask("(99) 99999-999?9");  
            } else {  
                element.mask("(99) 9999-9999?9");  
            }  
});
	
<?php
if($StatusCaptcha == "S"){
?>
function NovoCaptcha(){
			
			panel_refresh($(".registration-container"));

			$.post('CaptchaImg.php', function(resposta) {
				
			setTimeout(panel_refresh($(".registration-container")),500);
				
			$("#StatusCaptcha").html('');
			$("#StatusCaptcha").html(resposta);
						
			});
				
}
<?php
}
?>

function CriarTesteAutomatico(){
 
	   var Data = $(".TesteCadastrar").serialize();
		 
		panel_refresh($(".registration-container"));
				
		$.post('EnviarCadTeste.php', Data, function(resposta) {
			
				setTimeout(panel_refresh($(".registration-container")),500);
			
				$("#StatusGeral").html('');
				$("#StatusGeral").append(resposta);
		});
}
	
$(function(){
	$(".TesteCadastrar select[name=OpcaoForm]").change(function(){
		
		var OpcaoForm = $(this).val();
		var CadUser = '<?php echo $CadUser; ?>';
		
		panel_refresh($(".registration-container"));
		
		$.post('ExibirSelectCadOpcao.php', {OpcaoForm: OpcaoForm, CadUser: CadUser}, function(resposta) {
			
				setTimeout(panel_refresh($(".registration-container")),500);
				
				$("#StatusOpcao").html('');
				$("#StatusOpcao").html(resposta);
		});
	});
});
</script>

<?php
}else{
	echo Redirecionar('login.php');
}
?>





