<?php
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;
$idioma = empty($_COOKIE['idioma']) ? "br" : $_COOKIE['idioma'];

$VerificarInfoSite = VerificarInfoSite();

$VerificarInfoOnline = VerificarInfoOnline();
$usuario = InfoUser(2);
$Foto = Foto($VerificarInfoOnline[3]);
$ExibirNome = empty($VerificarInfoOnline[0]) && empty($VerificarInfoOnline[1]) ? $usuario : $VerificarInfoOnline[0]."&nbsp;".$VerificarInfoOnline[1];
?>
<!DOCTYPE html>
<html lang="<?php echo $idioma; ?>" class="body-full-height">
    <head>        
        <!-- META SECTION -->
        <title><?php echo $VerificarInfoSite[0]. " - " .$_TRA['lb']; ?></title>            
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
        
        <div class="lockscreen-container">
            
            <div class="lockscreen-box animated fadeInDown">
                
                <div class="lsb-access">
                    <div class="lsb-box">
                        <div class="fa fa-lock"></div>
                        <div class="user animated fadeIn">
                            <img src="<?php echo $Foto; ?>" alt="<?php echo $ExibirNome; ?>"/>
                        </div>
                    </div>
                </div>
                
                <div class="lsb-form animated fadeInDown">
                    <form action="javascript:MDouglasMS();" method="post" class="AdicionarLiberarComputador form-horizontal">
                        <div class="form-group">
                            <div class="col-md-12">
                                <div class="input-group">
                                    <div class="input-group-addon">
                                        <span class="fa fa-mobile"></span>
                                    </div>
                                    <input onKeyPress="return EnviarEnterLibComputador(this,event)" name="CodigoSMS" id="CodigoSMS" type="text" class="form-control" placeholder="<?php echo $_TRA['cs']; ?>"/>
                                    <input id="ConfSMS" name="ConfSMS" type="hidden" value="2">
                                </div>
                            </div>
                        </div>
                        
                        
                        <input type="submit" class="hidden"/>
                    </form>
                </div>
            </div>
            
            <div class="StatusLiberarComputador"></div>
            
        </div>
    <!-- START SCRIPTS -->
        <!-- START PLUGINS -->
        <script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
        <script type="text/javascript" src="js/plugins/jquery/jquery-ui.min.js"></script>
        <script type="text/javascript" src="js/plugins/bootstrap/bootstrap.min.js"></script>        
        <!-- END PLUGINS -->

        <!-- START TEMPLATE -->                
        <script type="text/javascript" src="js/plugins.js"></script>
        <script type="text/javascript" src="js/actions.js"></script>
        <!-- END TEMPLATE -->
                
		<script>
		$(function(){
			$(".lockscreen-box .lsb-access").on("click",function(){
				
				var Data = $(".AdicionarLiberarComputador").serialize();
				
				$("#ConfSMS").attr('value', 1);
				
				panel_refresh($(".AdicionarLiberarComputador")); 
				
				$.post('EnviarLiberarComputadorExterno.php', Data, function(resposta) {
					setTimeout(panel_refresh($(".AdicionarLiberarComputador")),500);
					$(".StatusLiberarComputador").html('');
					$(".StatusLiberarComputador").append(resposta);
				});
				
				
			});
		});
		
		function EnviarEnterLibComputador(myfield,e){
			
			var keycode;
			if (window.event) keycode = window.event.keyCode;
			else if (e) keycode = e.which;
			else return true;
			
			if (keycode == 13){
				
			var Data = $(".AdicionarLiberarComputador").serialize();
				
			panel_refresh($(".AdicionarLiberarComputador")); 
				
			$.post('EnviarLiberarComputadorExterno.php', Data, function(resposta) {
				setTimeout(panel_refresh($(".AdicionarLiberarComputador")),500);
				$(".StatusLiberarComputador").html('');
				$(".StatusLiberarComputador").append(resposta);
			});
			
			}
			
		}
		</script>
        
        
    <!-- END SCRIPTS --> 
    </body>
</html>
