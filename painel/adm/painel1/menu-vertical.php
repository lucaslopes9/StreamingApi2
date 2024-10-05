<?php
include("conexao.php");
include_once("functions.php");
include_once(Idioma(1));
global $_TRA;
if(ProtegePag() == true){
$UserOnline = InfoUser(2);
$AcessoOnline = InfoUser(3);
?>
<script type="text/javascript" src="js/plugins/jquery/jquery.min.js"></script>
<script type='text/javascript'>  
$(function(){  
 $("a.Sair").click(function() { 
 
 		var titulo = '<?php echo $_TRA['sair']; ?>?';
		var texto = '<?php echo $_TRA['tcds']; ?>';
		var tipo = 'danger';
		var link = 'sair.php';
		var fa = 'fa-sign-out';  
			
		$.post('ScriptAlerta.php', {titulo: titulo, texto: texto, tipo: tipo, link: link, fa: fa}, function(resposta) {
				$("#StatusGeral").html('');
				$("#StatusGeral").html(resposta);
		});
	});
});
</script>

<style>
.SpanIco{
	color:#FFF;
	height: 50px;
    display: flex;
	align-items: center; 
	justify-content: center;
}
</style>

<div id="StatusGeral"></div>

<!-- START X-NAVIGATION VERTICAL -->
                <ul class="x-navigation x-navigation-horizontal x-navigation-panel">
                
                    <!-- TOGGLE NAVIGATION -->
                    <li class="xn-icon-button">
                        <a href="#" class="x-navigation-minimize"><span class="fa fa-dedent"></span></a>
                    </li>
                    <!-- END TOGGLE NAVIGATION -->
                    
                    <?php
					if($AcessoOnline != 1){
						$PrePago = empty($_SESSION['PrePago']) ? "N" : $_SESSION['PrePago'];
						$ConvertDataPremium = ConvertDataPremiumMenu($_SESSION['data_premio'], $PrePago);
					}
					else{
						$ConvertDataPremium = ConvertDataPremiumMenu('Admin');
					}
					echo "<li class=\"xn-icon-button\">
                        <span class=\"SpanIco\" style=\"width: 120px;\">".$ConvertDataPremium."</span>
                    </li>";
					?>
                                
                    <!-- POWER OFF -->
                    <li class="xn-icon-button pull-right last">
                        <a href="#"><span class="fa fa-power-off"></span></a>
                        <ul class="xn-drop-left animated zoomIn">
                            <li><a href="#" class="mb-control Sair"><span class="fa fa-sign-out"></span> <?php echo $_TRA['sair']; ?></a></li>
                        </ul>                        
                    </li> 
                    <!-- END POWER OFF -->                    
                    <!-- MESSAGES -->
                    <?php
					$LidaReceptor = "N";
					$SQLSuporte = "SELECT id, UserEmissor, UserReceptor, Assunto, PastaReceptor, PastaEmissor FROM suporte WHERE UserReceptor = :UserReceptor AND LidaReceptor = :LidaReceptor OR UserEmissor = :UserEmissor AND LidaEmissor = :LidaEmissor";
					$SQLSuporte = $painel_geral->prepare($SQLSuporte);
					$SQLSuporte->bindParam(':UserReceptor', $UserOnline, PDO::PARAM_STR);
					$SQLSuporte->bindParam(':LidaReceptor', $LidaReceptor, PDO::PARAM_STR);
					$SQLSuporte->bindParam(':UserEmissor', $UserOnline, PDO::PARAM_STR);
					$SQLSuporte->bindParam(':LidaEmissor', $LidaReceptor, PDO::PARAM_STR);
					$SQLSuporte->execute();
  					$TotalSuporte = count($SQLSuporte->fetchAll());
					
					$LinkSuporte = $TotalSuporte > 0 ? "#" : "index.php?p=suporte&a=1";
					
					echo "<li class=\"xn-icon-button pull-right\">
                        <a href=\"".$LinkSuporte."\"><span class=\"fa fa-envelope\"></span></a>";
						
						if($TotalSuporte > 0){
                       	echo "<div class=\"informer informer-danger\">".$TotalSuporte."</div>";						
                        echo "<div class=\"panel panel-primary animated zoomIn xn-drop-left xn-panel-dragging\">
                            <div class=\"panel-heading\">
                                <h3 class=\"panel-title\"><span class=\"fa fa-envelope\"></span> ".$_TRA['Mensagem']."</h3>";                                
								if($TotalSuporte > 0){
									
									$SsSuporte = $TotalSuporte > 1 ? $_TRA['Novas'] : $_TRA['Nova'];
									
                               	 	echo "<div class=\"pull-right\">
                                    <span class=\"label label-danger\">".$TotalSuporte." ".$SsSuporte."</span>
                                	</div>";
								}
								
							$HeightMensagem = $TotalSuporte < 5 ? 65*$TotalSuporte : 260;												
                            echo "</div>
                            <div class=\"panel-body list-group list-group-contacts scroll\" style=\"height: ".$HeightMensagem."px;\">";
							
							$SQLSuporte->execute();
  							while($LnSuporte = $SQLSuporte->fetch()){
								
								$UserVer = $UserOnline == $LnSuporte['UserEmissor'] ? $LnSuporte['UserReceptor'] : $LnSuporte['UserEmissor'];
								$PastaVer = $UserOnline == $LnSuporte['UserEmissor'] ? $LnSuporte['PastaEmissor'] : $LnSuporte['PastaReceptor'];

								$SQLUserE = "SELECT foto FROM admin WHERE usuario = :usuario 
								UNION ALL SELECT foto FROM rev WHERE usuario = :usuario
								UNION ALL SELECT foto FROM teste WHERE usuario = :usuario
								UNION ALL SELECT foto FROM usuario WHERE usuario = :usuario
								";
								$SQLUserE = $painel_user->prepare($SQLUserE);
								$SQLUserE->bindParam(':usuario', $UserVer, PDO::PARAM_STR);
								$SQLUserE->execute();
  								$LnUserE = $SQLUserE->fetch();
								
								$FotoEmissor = Foto($LnUserE['foto']);
								
                                echo "<a href=\"index.php?p=suporte&a=".$PastaVer."&m=".$LnSuporte['id']."\" class=\"list-group-item\">
                                    <img src=\"".$FotoEmissor."\" class=\"pull-left\" alt=\"".$UserVer."\"/>
                                    <span class=\"contacts-title\">".$UserVer."</span>
                                    <p>".LimitarTexto($LnSuporte['Assunto'], 40)."</p>
                                </a>";
							}
                               
                            echo "</div>     
                            <div class=\"panel-footer text-center\">
                                <a href=\"index.php?p=suporte&a=1\">".$_TRA['vtam']."</a>
                            </div>                            
                        </div>";
						           
						}
                    echo "</li>";
					?>
                    <!-- END MESSAGES -->
                    
                    <?php echo RedesSociais(); ?>

                    <!-- LANG BAR -->
                    <li class="xn-icon-button pull-right">
                        <a href="#"><span class="flag flag<?php echo Idioma(2); ?>"></span></a>
                       <ul class="xn-drop-left xn-drop-white animated zoomIn">
                       <?php
					   echo IdiomaMenu();
					   ?>
                       </ul>                        
                    </li> 
                    <!-- END LANG BAR -->
                </ul>
                <!-- END X-NAVIGATION VERTICAL --> 
                
<?php
}else{
	echo Redirecionar('login.php');
}
?>