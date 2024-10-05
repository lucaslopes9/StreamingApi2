<?php
if(isset($_POST['submit'])){      
      echo("SENHA: " . $_POST['senha'] . "<br />");	  
	  $string = md5(md5(md5(md5(md5($_POST['senha']))))); 
	  echo("MD5: " . $string . "<br />");
   }
  
?>
<form action="#" method="post">
   <p>Senha: <input type="text" name="senha" /></p>
   
   <input type="submit" name="submit" value="Submit" />
</form>