<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;
$idioma = empty($_COOKIE['idioma']) ? "br" : $_COOKIE['idioma'];

$VerificarInfoSite = VerificarInfoSite();

$SQL = "SELECT status FROM captcha";
$SQL = $painel_geral->prepare($SQL);
$SQL->execute();
$Ln = $SQL->fetch();
$captcha = $Ln['status'];
?>
<!DOCTYPE html>
<html lang="<?php echo $idioma; ?>" class="body-full-height">
    <head>        
        <!-- META SECTION -->
        <title><?php echo $VerificarInfoSite[0]. " - " .$_TRA['Entrar']; ?></title>            
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

        <div class="login-container">
        
            <div class="login-box animated fadeInDown">
                <div class="login-logo"><?php echo $VerificarInfoSite[0]; ?></div>
				<div class="login-legenda"><?php echo $VerificarInfoSite[1]; ?></div>
                <div class="login-body">
                    <div class="login-title"><strong><?php echo $_TRA['SBV']; ?></strong>, <?php echo $_TRA['Entrar']; ?></div>
                    <form id="FormLogin" name="FormLogin" class="FormLogin form-horizontal" method="POST" action="javascript:FormLogin()">
                    <div class="form-group">
                        <div class="col-md-12">
                            <input type="text" name="usuario" id="usuario" class="form-control" placeholder="<?php echo $_TRA['Usuario']; ?>"/>
                        </div>
                    </div>
                    <div class="form-group">
                        <div class="col-md-12">
                            <input type="password" name="senha" id="senha" class="form-control" placeholder="<?php echo $_TRA['Senha']; ?>"/>
                        </div>
                    </div>
                    
                    <?php
					if($captcha == "S"){
					?>
                    
                    <div class="form-group">
                   		<center>
                   	 		<div id="StatusCaptcha">
           						<?php include "CaptchaImg.php"; ?>
           					</div>
                        </center>
                    </div>
                    
                    <div class="form-group pointer" onClick="NovoCaptcha()">
                   	 	<div class="col-md-12 text-right" align="right">
                    		<font color="#FFFFFF">Novo Captcha</font>
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
                    
                    <div class="form-group">
                   	    <div id="StatusLogin"></div>
                    	<div class="col-md-12">
                            <button onClick="FazerLoginIPTV()" class="btn btn-info btn-block"><?php echo $_TRA['Entrar']; ?></button>
                        </div>
                    </div>
                    
                    </form>
                </div>
                <div class="login-footer">
                    <div class="pull-left">
                        &copy; <?php echo $VerificarInfoSite[0]; ?>
    </div>
            </div>

               
                </div>
            </div>
            
        </div>

<script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
<script type="text/javascript" src="js/plugins.js"></script>  
<script type="text/javascript" src="js/actions.js"></script>

<script>
<?php
if($captcha == "S"){
?>
function NovoCaptcha(){
			
			panel_refresh($(".login-container"));

			$.post('CaptchaImg.php', function(resposta) {
				
			setTimeout(panel_refresh($(".login-container")),500);
				
			$("#StatusCaptcha").html('');
			$("#StatusCaptcha").html(resposta);
						
			});
				
}
<?php
}
?>
	
function FazerLoginIPTV(){
 
	    var Data = $(".FormLogin").serialize();
		 
		panel_refresh($(".login-container"));
				
		$.post('validar-login.php', Data, function(resposta) {
			
				setTimeout(panel_refresh($(".login-container")),500);
			
				$("#StatusGeral").html('');
				$("#StatusGeral").append(resposta);
		});
}
</script>

<div id="StatusGeral"></div>

    </body>
</html>